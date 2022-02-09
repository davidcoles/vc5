#!/usr/bin/env perl
use strict;
use YAML;
use JSON;
use Socket;
use feature qw(switch);
no warnings qw(experimental::smartmatch); 

use Getopt::Std;

getopts('h', \my %opts);

{
    my $conf = YAML::Load(join('', <>));
    
    my $s = $conf->{'services'} or die;
    my $r = $conf->{'reals'} or die;
    my $v = $conf->{'vlans'};
    $v = {} unless defined $v;

    foreach(keys %$v) {
	$v->{$_} += 0;
    }
    
    my $services = services($s, $r);
    #my $peers = peers($p);
    #my $peers = $p;
    my $rhi = $conf->{'rhi'} or die;
    $rhi->{'as_number'} =  $rhi->{'as_number'}+0;

    #my $json = { 'peers' => $peers, 'services' => $services, 'multicast' => $conf->{'multicast'} };
    my $json = {
	    'learn' => $conf->{'learn'}+0,
	    'services' => $services,
	    'multicast' => $conf->{'multicast'},
	    'webserver' => $conf->{'webserver'},
	    'rhi' => $rhi,
	    'vlans' => $v,
    };
    
    print to_json($json, {pretty=>1}),"\n";
}

sub peers {
    my($peers) = @_;
    my @p;
    foreach my $p (@$peers) {
	push(@p, [map {$_+0}split('\.', lookup($p))]);
    }
    return [@p];
}

sub services {
    my($s, $r) = @_;

    my @list;
    
    foreach(@$s) {
	my $name = $_->{'name'};
	my $desc = $_->{'desc'};
	my $port = $_->{'port'};
	my $need = $_->{'need'} + 0;
	my $conn = $_->{'least'} ? JSON::true : JSON::false;
	my @port = ref($_->{'port'}) eq 'ARRAY' ? @{$_->{'port'}} : ($_->{'port'});
	my @real = ref($_->{'real'}) eq 'ARRAY' ? @{$_->{'real'}} : ($_->{'real'});
	my @addr = ref($_->{'addr'}) eq 'ARRAY' ? @{$_->{'addr'}} : ($_->{'addr'});
	my @rips = map { @{$r->{$_}} } @real;
	
	my @checks = ref($_->{'checks'}) eq 'ARRAY' ? @{$_->{'checks'}} : ($_->{'checks'});
	my @http;
	my @https;
	my @tcp;
	my @syn;

	my($port) = @port;

	foreach my $c (@checks) {
	    given($c->{'type'}) {
		when ("http") {
		    my $url = $c->{'path'};
		    my $exp = defined $c->{'expect'} ? $c->{'expect'} : 200;
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    my $hst = defined $c->{'host'} ? $c->{'host'} : "";
		    push(@http, {'method' => 'GET', 'path' => $url, 'expect' => $exp+0, 'port' => $prt+0, 'host' => $hst});
		}
		when ('https') {
		    my $url = $c->{'path'};
		    my $exp = defined $c->{'expect'} ? $c->{'expect'} : 200;
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    my $hst = defined $c->{'host'} ? $c->{'host'} : "";
		    push(@https, {'method' => 'GET', 'path' => $url, 'expect' => $exp+0, 'port' => $prt+0, 'host' => $hst});
		}
		when ('tcp') {
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    push(@tcp, {'port' => $prt+0});
		}
		when ('syn') {
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    push(@syn, {'port' => $prt+0});
		}
	    }
	}

	$need = 1 unless $need > 0;

	foreach my $v (@addr) {
	    foreach my $p (@port) {
		my $x = {};
		#$x->{'vip'} = [map {$_+0} split('\.', $v)];
		$x->{'vip'} = lookup($v);
		$x->{'port'} = $p+0;
		$x->{'name'} = $name;
		$x->{'need'} = $need;
		$x->{'description'} = $desc;
		$x->{'leastconns'} = $conn;;
		my @rip;
		foreach my $r (@rips) {
		    my $y = {};
		    #$y->{'rip'} = [map {$_+0}split('\.', lookup($r))];
		    $y->{'rip'} = lookup($r);
		    $y->{'http'} = \@http if scalar(@http);
		    $y->{'https'} = \@https if scalar(@https);
		    $y->{'tcp'} = \@tcp if scalar(@tcp);
		    $y->{'syn'} = \@syn if scalar(@syn);
		    
		    push(@rip, $y);
		}
		$x->{'rip'} = \@rip;
		
		push(@list, $x);
	    }
	}
    }
    
    return \@list;
}

sub lookup {
    my($name) = @_;
    my $n = inet_aton($name);
    die "$name: lookup failed\n" unless length($n) == 4;
    my $address = inet_ntoa($n);
    die "$name: lookup failed\n" unless $address =~ /^\d+\.\d+\.\d+\.\d+$/;
    return $address;
}

