#!/usr/bin/env perl
use strict;
use YAML;
use JSON;
use Socket;
use feature qw(switch);
no warnings qw(experimental::smartmatch); 

use Getopt::Std;

getopts('h', \my %opts);


if(1) {
    my $conf = YAML::Load(join('', <>));
    my $policy = $conf->{'policy'};
    my $service = $conf->{'services'};
    my $servers = $conf->{'servers'};
    
    my @s = readconf($service, $policy, $servers);
    if($opts{h}) {print to_json(\@s, {pretty => 1}); exit;}


    $conf->{'learn'}+=0 if defined $conf->{'learn'};
    $conf->{'rhi'}->{'as_number'}+= 0 if defined $conf->{'rhi'}->{'as_number'};

    my $out = {};

    foreach(qw(learn multicast rhi webserver interfaces vlans)) {
	$out->{$_} = $conf->{$_} if exists $conf->{$_};
    }

    
    my @S;
    
    foreach my $s (@s) {
	my @a;

	given(ref($s->{_addr})) {
	    when ('ARRAY') { @a = @{$s->{_addr}} }
	    when('') { @a = ( $s->{_addr} ) }
	}
	
	foreach my $a (@a) {
	    
	    my %i;
	    
	    
	    $i{'port'} = $s->{_port};
	    $i{'vip'} = $a;
	    $i{'need'} = defined $s->{_need} ? $s->{_need}+0 : 1;
	    $i{'udp'} = $s->{_udp} ? JSON::true : JSON::false;

	    $i{'name'} = $s->{_name};
	    $i{'description'} = $s->{_desc};
	    
	    
	    my @r;
	    my %r;
	    {
		my @h;
		my @H;
		my @t;
		my @s;

		if(0) {
		    my $c = $s->{_check};
		    
		    if(defined $c) {
			given($c->{_type}) {
			    when ('http') { push @h, httpchk($c) }
			when ('https') { push @H, httpchk($c) }
			    when ('tcp') { push @t, { 'port' => $c->{_port} } }
			    when ('syn') { push @s, { 'port' => $c->{_port} } }
			}
		    }
		} else {
		    my $c = $s->{_checks};
		    if(defined $c) {
			foreach my $C (@$c) {
			    given($C->{_type}) {
				when ('http') { push @h, httpchk($C) }
				when ('https') { push @H, httpchk($C) }
				when ('tcp') { push @t, { 'port' => $C->{_port} } }
				when ('syn') { push @s, { 'port' => $C->{_port} } }
			    }
			}
		    }
		}
		
		foreach(@{$s->{_real}}) {
		    my %r;
		    #$r{'rip'} = $_->{_addr};
		    $r{'http'} = \@h if scalar(@h) > 0;
		    $r{'https'} = \@H if scalar(@H) > 0;
		    $r{'tcp'} = \@t if scalar(@t) > 0;
		    $r{'syn'} = \@s if scalar(@s) > 0;
		    
		    #push(@r, \%r);
		    $i{'rip'}{$_->{_addr}} = \%r;
		}
	    }

	    #$i{'rip'} = \@r;
	    #foreach(@r) {
	#	$i{'rip'}{$_->{'rip'}} = $_;
	 #   }
	    
	    push(@S, \%i);	
	}
    }
    
    #$out->{'services'} = \@S;


    my $foo = {};
    foreach(@S) {
	my $i = $_->{'vip'};
	my $p = $_->{'port'};
	my $u = $_->{'udp'};
	my $n = $u ? "udp:" : "tcp:";
	$n .= $p;

	delete($_->{'vip'});
	delete($_->{'udp'});
	delete($_->{'port'});
	
	$foo->{$i}->{$n} = $_;
    }
    $out->{'vips'} = $foo;
    
    print to_json($out, {pretty => 1, canonical => 1});
}

sub httpchk {
    my($c) = @_;
    return {
	'path' => $c->{_path},
	    'port' => $c->{_port},
	    'host' => $c->{_host},
	    'expect' => $c->{_expt},
	    'method' => 'GET',
    };
}

sub readconf {
    my @s;
    my($s, $pol, $srv) = @_;
    my $DEFAULT = { 'http' => {}, 'https' => {} };
    my %ip;

	
    
    foreach(@$s) {
	my $a = $_->{'address'};
	my $h = $_->{'host'};
	my $n = $_->{'name'};
	my $d = $_->{'description'};
	my $P = $_->{'path'};
	my $N = $_->{'need'};	
	my $b = $_->{'predictor'};
	my %r;

	if(ref($_->{'servers'}) eq 'HASH') {
	    %r = %{$_->{'servers'}};	
	} elsif(ref($_->{'servers'}) eq 'ARRAY') {
	    %r = map { $_ => $_ } @{$_->{'servers'}};
	} else {
	    my $k = $_->{'servers'};
	    %r = map { $_ => $_ } @{$srv->{$k}};
	}


 	die "$b\n" unless !defined $b || $b =~ /^(roundrobin|leastconn|first|source)$/;

	
	my $policy = $_->{'policy'};
	$policy = $DEFAULT unless defined $policy;
	
	if(ref($policy) eq '') {
	    my $p = $pol->{$policy};
	    die "Missing policy $policy\n" unless defined $p;
	    $policy = $p;
	}

	my %policy = %$policy;

	my @ret = policy($a, $h, $P, $n, $d, $N, \%r, %policy);
	
	push(@s, @ret);
	
    }

    @s;
}


sub policy {
    my($a, $h, $P, $n, $d, $need, $r, %policy) = @_;

    my %r = %$r;
    my @s;
    
    foreach my $pol (sort keys %policy) {
	my $v = $policy{$pol};
	my %p = defined $policy{$pol} ? %{$policy{$pol}} : ();
	my $check = { _type => 'none' };
	my $port = 0;
	my $bind = 0;
	#my $expt = defined $p ? $p : undef;
	my $expt;
	my $host = defined $h ? $h : undef;
	my $path = defined $P ? $P : undef;
	
	my $udp = 0;

	my @c;

	if(exists $policy{$pol}{'need'}) {
	    $need = $policy{$pol}{'need'} + 0;
	}

	
	given($pol) {
	    when('http' ) { $port =  80; }
	    when('https') { $port = 443; }

	    when('dns')     { $port = 53; $udp = 0; }
	    when('dns/tcp') { $port = 53; $udp = 0; }
	    when('dns/udp') { $port = 53; $udp = 1; }
	    
	    when(m/^[1-9][0-9]*$/)       { $port = $pol+0; }
	    when(m:^([1-9][0-9]*)/udp$:) { $port = $1+0; $udp = 1; }
	    when(m:^([1-9][0-9]*)/tcp$:) { $port = $1+0; $udp = 0; }
	    default {
		die "oops '$pol' ",%p," \n";
	    }
	}
	
	@c = check($pol, $port, $udp, $host, $path, $expt, $v);
	
	my @R = map { {_name => defined $r{$_} ? $r{$_} : $_, _addr => $_, _port => $bind} } sort keys %r;
	
	my $e = {
	    _addr => $a,
	    _port => $port,
	    _name => $n,
	    _desc => $d,
	    _need => $need,
	    _real => \@R,
	    _udp => $udp,
	    _checks => \@c,
	    _balance => defined $b ? $b :'roundrobin',
	};
	
	push @s, $e;
    }

    @s;
}

sub check {
    my($p, $port, $udp, $host, $path, $expt, $foo) = @_;

    my @c;

    if(defined $foo->{'checks'}) {
	foreach(@{$foo->{'checks'}}) {
	    my %c = %$_;

	    my $type = $c{'type'};


	    $host = defined $c{'host'} ? $c{'host'} : $host;
	    $path = defined $c{'path'} ? $c{'path'} : $path;
	    $expt = defined $c{'expt'} ? $c{'expt'}+0 : $expt;


	    $path = '/' unless defined $path;
	    $expt = 200 unless defined $expt;
	    

	    $port = $c{'port'}+0 if defined $c{'port'};
	    
	    push @c, { _type => $type, _path => $path, _expt => $expt, _port => $port, _host => $host} };
    } else {
	given($p) {
	    $path = '/' unless defined $path;
	    $expt = 200 unless defined $expt;
	    when('http' ) { push @c, { _type => "http",  _port => $port, _path => $path, _expt => $expt, _host => $host} };
	    when('https') { push @c, { _type => "https", _port => $port, _path => $path, _expt => $expt, _host => $host} };
	    when('dns' )  { push @c, { _type => "syn",   _port => $port } };
	}
    }
    
    return @c;
}
