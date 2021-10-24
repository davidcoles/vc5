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
    my $json = { 'learn' => $conf->{'learn'}+0, 'services' => $services, 'multicast' => $conf->{'multicast'}, 'rhi' => $rhi, 'vlans' => $v };
    
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
	my @port = ref($_->{'port'}) eq 'ARRAY' ? @{$_->{'port'}} : ($_->{'port'});
	my @real = ref($_->{'real'}) eq 'ARRAY' ? @{$_->{'real'}} : ($_->{'real'});
	my @addr = ref($_->{'addr'}) eq 'ARRAY' ? @{$_->{'addr'}} : ($_->{'addr'});
	my @rips = map { @{$r->{$_}} } @real;
	
	my @checks = ref($_->{'checks'}) eq 'ARRAY' ? @{$_->{'checks'}} : ($_->{'checks'});
	my @http;
	my @https;
	my @tcp;

	my($port) = @port;

	foreach my $c (@checks) {
	    given($c->{'type'}) {
		when ("http") {
		    my $url = $c->{'path'};
		    my $exp = defined $c->{'expect'} ? $c->{'expect'} : 200;
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    push(@http, {'method' => 'GET', 'path' => $url, 'expect' => $exp+0, 'port' => $prt+0});
		}
		when ('https') {
		    my $url = $c->{'path'};
		    my $exp = defined $c->{'expect'} ? $c->{'expect'} : 200;
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    push(@https, {'method' => 'GET', 'path' => $url, 'expect' => $exp+0, 'port' => $prt+0});
		}
		when ('tcp') {
		    my $prt = defined $c->{'port'} ? $c->{'port'} : $port;
		    push(@tcp, {'port' => $prt+0});
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
		my @rip;
		foreach my $r (@rips) {
		    my $y = {};
		    #$y->{'rip'} = [map {$_+0}split('\.', lookup($r))];
		    $y->{'rip'} = lookup($r);
		    $y->{'http'} = \@http if scalar(@http);
		    $y->{'https'} = \@https if scalar(@https);
		    $y->{'tcp'} = \@tcp if scalar(@tcp);		    
		    
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










__END__;
sub haproxy {
    my($v, $b) = @_;

    my @list;
    
    foreach(@$v) {
	my $vhost = $_->{'vhost'};
	my $https = $_->{'https'};
	my $port = $_->{'port'};
	my @port = ref($_->{'port'}) eq 'ARRAY' ? @{$_->{'port'}} : ($_->{'port'});
	my @real = ref($_->{'real'}) eq 'ARRAY' ? @{$_->{'real'}} : ($_->{'real'});
	my @addr = ref($_->{'addr'}) eq 'ARRAY' ? @{$_->{'addr'}} : ($_->{'addr'});
	my @reals = map { @{$b->{$_}} } @real;
	
	my @checks = ref($_->{'checks'}) eq 'ARRAY' ? @{$_->{'checks'}} : ($_->{'checks'});

	push(@list, $vhost);

	#option httpchk HEAD / HTTP/1.1\r\nHost:\ example.com


	print <<EOF;
frontend $vhost

EOF
	
    }

}


__END__;
global
	log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
	stats timeout 30s
	user haproxy
	group haproxy
	daemon

	# Default SSL material locations
	#ca-base /etc/ssl/certs
	crt-base /etc/ssl/private

	# See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
        ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
        timeout connect 5000
        timeout client  50000
        timeout server  50000
	errorfile 400 /etc/haproxy/errors/400.http
	errorfile 403 /etc/haproxy/errors/403.http
	errorfile 408 /etc/haproxy/errors/408.http
	errorfile 500 /etc/haproxy/errors/500.http
	errorfile 502 /etc/haproxy/errors/502.http
	errorfile 503 /etc/haproxy/errors/503.http
	errorfile 504 /etc/haproxy/errors/504.http


backend Abuse
    stick-table type ip size 1m expire 30s store conn_rate(60s),conn_cur,gpc0,http_req_rate(60s),http_err_rate(60s)
    
frontend http-in
    bind *:80
    bind :443 ssl crt ./
    mode http
    #http-request redirect scheme https unless { ssl_fc }
    tcp-request connection reject if { src_conn_rate(Abuse) ge 200 }
    tcp-request connection reject if { src_conn_cur(Abuse) ge 50 }
    tcp-request connection reject if { src_http_err_rate(Abuse) ge 50 }
    tcp-request connection track-sc1 src table Abuse
    acl is_nginx path_beg /repo/
    acl is_nginx path_beg /bsplayer/
    use_backend nginx if is_nginx
    default_backend uwsgi


backend uwsgi
    server foo 127.0.0.1:8000
    mode http

backend nginx
    server foo 127.0.0.1:8080
    mode http


    
