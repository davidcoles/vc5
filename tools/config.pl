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
	    $i{'sticky'} = $s->{_sticky} ? JSON::true : JSON::false;
	    $i{'leastconns'} = $s->{_leastconns} ? JSON::true : JSON::false;	    
	    
	    
	    my @r;
	    my %r;
	    {
		my @http;
		my @https;
		my @tcp;
		my @syn;

		if(0) {
		    my $c = $s->{_check};
		    
		    if(defined $c) {
			given($c->{_type}) {
			    when ('http')   { push @http, httpchk($c) }
			    when ('https') { push @https, httpchk($c) }
			    when ('tcp')   { push @tcp,   { 'port' => $c->{_port} } }
			    when ('syn')   { push @syn,   { 'port' => $c->{_port} } }
			}
		    }
		} else {
		    my $c = $s->{_checks};
		    if(defined $c) {
			foreach my $C (@$c) {
			    given($C->{_type}) {
				when ('http')  { push @http,  httpchk($C) }
				when ('https') { push @https, httpchk($C) }
				when ('tcp')   { push @tcp,   { 'port' => $C->{_port} } }
				when ('syn')   { push @syn,   { 'port' => $C->{_port} } }
			    }
			}
		    }
		}
		
		foreach(@{$s->{_real}}) {
		    my %r;
		    $r{'http'}  = \@http  if scalar(@http) > 0;
		    $r{'https'} = \@https if scalar(@https) > 0;
		    $r{'tcp'}   = \@tcp   if scalar(@tcp) > 0;
		    $r{'syn'}   = \@syn   if scalar(@syn) > 0;
		    
		    $i{'rips'}{$_->{_addr}} = \%r;
		}
	    }
	    
	    push(@S, \%i);	
	}
    }
    
    my $vips = {};
    foreach(@S) {
	my $vip = $_->{'vip'};
	my $l4 = sprintf "%s:%d", $_->{'udp'} ? "udp" : "tcp", $_->{'port'};
	
	delete($_->{'vip'});
	delete($_->{'udp'});
	delete($_->{'port'});
	
	$vips->{$vip}->{$l4} = $_;
    }
    $out->{'vips'} = $vips;
    
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
	my $addr = $_->{'address'};
	my $host = $_->{'host'};
	my $name = $_->{'name'};
	my $desc = $_->{'description'};
	my $path = $_->{'path'};
	my $need = $_->{'need'};	
	my $pred = $_->{'predictor'};
	my $sticky = $_->{'sticky'} ? JSON::true : JSON::false;
	my $leastconns = $_->{'leastconns'} ? JSON::true : JSON::false;	
	my %r;

	if(ref($_->{'servers'}) eq 'HASH') {
	    %r = %{$_->{'servers'}};	
	} elsif(ref($_->{'servers'}) eq 'ARRAY') {
	    %r = map { $_ => $_ } @{$_->{'servers'}};
	} else {
	    my $k = $_->{'servers'};
	    %r = map { $_ => $_ } @{$srv->{$k}};
	}


 	die "$pred\n" unless !defined $pred || $pred =~ /^(roundrobin|leastconn|first|source)$/;

	
	my $policy = $_->{'policy'};
	$policy = $DEFAULT unless defined $policy;
	
	if(ref($policy) eq '') {
	    my $p = $pol->{$policy};
	    die "Missing policy $policy\n" unless defined $p;
	    $policy = $p;
	}

	my %policy = %$policy;

	my @ret = policy($addr, $host, $path, $name, $desc, $need, $sticky, $leastconns, \%r, %policy);
	
	push(@s, @ret);
	
    }

    @s;
}


sub policy {
    my($a, $host_, $path_, $name_, $desc_, $need_, $sticky_, $leastconns_, $r, %policy) = @_;

    my %r = %$r;
    my @s;
    
    foreach my $pol (sort keys %policy) {
	my $v = $policy{$pol};
	my %p = defined $policy{$pol} ? %{$policy{$pol}} : ();
	my $check = { _type => 'none' };
	my $port = 0;
	my $bind = 0;
	my $expt;
	my $host = defined $host_ ? $host_ : undef;
	my $path = defined $path_ ? $path_ : undef;
	my $udp = 0;

	my @c;

	my $need = $need_;
	my $sticky = $sticky_;
	my $leastconns = $leastconns_;
	
	if(exists $policy{$pol}{'need'}) {
	    $need = $policy{$pol}{'need'} + 0;
	}

	if(exists $policy{$pol}{'sticky'}) {
	    $sticky = $policy{$pol}{'sticky'};
	}

	if(exists $policy{$pol}{'leastconns'}) {
	    $leastconns = $policy{$pol}{'leastconns'};
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
	    _name => $name_,
	    _desc => $desc_,
	    _need => $need,
	    _real => \@R,
	    _udp => $udp,
	    _sticky => $sticky,
	    _leastconns => $leastconns,	    
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
