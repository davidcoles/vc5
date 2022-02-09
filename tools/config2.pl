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
    #print to_json(\@s, {pretty => 1}); exit;


    $conf->{'learn'}+=0 if defined $conf->{'learn'};
    $conf->{'rhi'}->{'as_number'}+= 0 if defined $conf->{'rhi'}->{'as_number'};

    my $out = {};

    foreach(qw(learn multicast rhi webserver)) {
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
	    $i{'need'} = 1;

	    $i{'name'} = $s->{_name};
	    $i{'description'} = $s->{_desc};
	    
	    
	    my @r;
	    {
		my @h;
		my @H;
		my @t;
		my @s;
		my $c = $s->{_check};
		
		if(defined $c) {
		    given($c->{_type}) {
			when ('http') { push @h, httpchk($c) }
			when ('https') { push @H, httpchk($c) }
			when ('tcp') { push @t, { 'port' => $c->{_port} } }
			when ('syn') { push @s, { 'port' => $c->{_port} } }
		    }
		}
		
		foreach(@{$s->{_real}}) {
		    my %r;
		    $r{'rip'} = $_->{_addr};
		    $r{'http'} = \@h if scalar(@h) > 0;
		    $r{'https'} = \@H if scalar(@H) > 0;
		    $r{'tcp'} = \@t if scalar(@t) > 0;
		    $r{'syn'} = \@s if scalar(@s) > 0;
		    
		    push(@r, \%r);
		}
	    }

	    $i{'rip'} = \@r;
	    
	    push(@S, \%i);	
	}
    }
    
    $out->{'services'} = \@S;
    
    print to_json($out, {pretty => 1, canonical => 1});
}

sub httpchk {
    my($c) = @_;
    return {
	'path' => $c->{_path},
	    'port' => $c->{_port},
	    'host' => $c->{_host},
	    'expect' => $c->{_expect},
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


	foreach my $p (sort keys %policy) {
	    my %p = defined $policy{$p} ? %{$policy{$p}} : ();
	    my $check = { _type => 'none' };
	    my $port = 0;
	    my $bind = 0;
	    my $expt = defined $p{'expect'} ? $p{'expect'}+0 : 200;
	    my $host = defined $h ? $h : $p{'host'};
	    my $path = defined $p{'path'} ? $p{'path'} : '/';
	    $path = $P if defined $P;

	    given($p) {
		when('http') {
		    $port = 80;
		    $bind = defined $p{'port'} ? $p{'port'}+0 : $port;
		    $check = { _type => $p, _path => $path, _expect => $expt, _port => $bind, _host => $host };
		}
		when('https') {
		    $port = 443;
		    $bind = defined $p{'port'} ? $p{'port'}+0 : $port;		    
		    $check = { _type => $p, _path => $path, _expect => $expt, _port => $bind, _host => $host };
		}
		when(/^[1-9][0-9]*$/) {
		    $port = $p+0;
		    $bind = defined $p{'port'} ? $p{'port'}+0 : $port;
		    my $type = defined $p{'type'} ? $p{'type'} : 'none';
		    $check = { _type => $type, _path => $path, _expect => $expt,  _port => $bind, _host => $host };
		}
		default {
		    die "oops '$p' ",%p," \n";
		}
	    }
	    my $c = $p{'check'};
	    if(defined $c) {
		if(ref($c) eq '') {
		    given($c) {
			when ('none') { $check = { _type => 'none' } }
			default { die "check $c\m" }
		    }
		} else {
		    $check->{_type} = $c->{'type'} if defined $c->{'type'};
		    $check->{_path} = $c->{'path'} if defined $c->{'path'};
		    $check->{_port} = $c->{'port'} if defined $c->{'port'};
		    $check->{_expect} = $c->{'expect'}+0 if defined $c->{'expect'};
		    $check->{_method} = $c->{'method'} if defined $c->{'method'};
		}
	    }
	    $check->{_path} = $P if defined $P;
	    $check->{_host} = $h if defined $h;

	    my @R = map { {_name => defined $r{$_} ? $r{$_} : $_, _addr => $_, _port => $bind} } sort keys %r;

	    my $e = {
		_addr => $a,
		_port => $port,
		_name => $n,
		_desc => $d,
		_real => \@R,
		_check => $check,
		_balance => defined $b ? $b :'roundrobin',
	    };

	    push @s, $e;
	}
    }

    @s;
}





