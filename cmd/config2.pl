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
    my $json = {};
    
    my $policy = $conf->{'policy'};
    my $services = $conf->{'services'};
    my $servers = $conf->{'servers'};
    
    my %defaults;
    
    my $scheduler = $conf->{'scheduler'} if exists $conf->{'scheduler'};
    
    $json->{'services'} = services($scheduler, $services, \%defaults);

    $conf->{'learn'}+=0 if defined $conf->{'learn'};
    $conf->{'rhi'}->{'listen'} = $conf->{'rhi'}->{'listen'} =~ /^(yes|true|on|y)$/i ? JSON::true : JSON::false;
    $conf->{'rhi'}->{'as_number'}+= 0 if defined $conf->{'rhi'}->{'as_number'};
    $conf->{'rhi'}->{'hold_time'}+= 0 if defined $conf->{'rhi'}->{'hold_time'};    
    
    foreach(qw(learn multicast rhi webserver interfaces vlans)) {
	$json->{$_} = $conf->{$_} if exists $conf->{$_};
    }
    
    print to_json($json, {pretty => 1, canonical => 1});
}

sub services {
    my($scheduler, $services, $defaults) = @_;
    my %defaults = %$defaults;
    
    
    my %out;
	

    foreach my $s (@$services) {

	$defaults{_host} = key($s, 'host',        undef); # checks
	$defaults{_path} = key($s, 'path',        undef); # checks
	$defaults{_meth} = key($s, 'method',      undef); # checks
	$defaults{_expc} = key($s, 'expect',      undef); # checks
	$defaults{_name} = key($s, 'name',        undef);
	$defaults{_desc} = key($s, 'description', undef);
	$defaults{_need} = key($s, 'need',        1)+0;
	$defaults{_stic} = key($s, 'sticky',      JSON::false);
	$defaults{_schd} = key($s, 'scheduler',   $scheduler);
	
	my @virtual;
	my @servers;
	my %policy;
	
	given(ref($s->{'virtual'})) {
	    when('ARRAY') { @virtual = @{$s->{'virtual'}}}
	    when('')  { @virtual = ($s->{'virtual'}) }
	    default { die }
	}

	given(ref($s->{'servers'})) {
	    when('ARRAY') { @servers = @{$s->{'servers'}}}
	    default { die }
	}
	
	given(ref($s->{'policy'})) {
	    when('HASH') { %policy = %{$s->{'policy'}}}
	    default { die }
	}

	my %servers;
	foreach(@servers) {
	    die "bad server: $_\n" unless /^(\d+\.\d+\.\d+\.\d+)(\*|)$/;
	    $servers{$1} = {_dsbl => $2 eq '' ? 0 : 1};
	}
	
	my @policy = policy(\%policy, \%defaults);

	foreach my $v (@virtual) {
	    foreach my $p (@policy) {
		my $l4 = $p->{_prot} . ':' . $p->{_port};
		my @p = %$p;

		my $svc = { 'need' => $p->{_need}+0, 'sticky' => jsonbool($p->{_stic}) };

		$svc->{'name'}        = $p->{_name} if defined $p->{_name};
		$svc->{'description'} = $p->{_desc} if defined $p->{_desc};
		$svc->{'scheduler'}   = $p->{_schd} if defined $p->{_schd};

		my %rips;

		my $checks = checkify(@{$p->{_chks}});

		my $bind =  $p->{_bind}+0;
		
		foreach my $s (sort keys %servers) {
		    $rips{$s.":$bind"} = {
			'checks'   => $checks,
		        'disabled' => $servers{$s}->{_dsbl} ? JSON::true : JSON::false,
		    }
		}
		
		$svc->{'reals'} = \%rips;
		
		$out{$v.":".$p->{_port}.":".$p->{_prot}} = $svc;
	    }
	}
    }
    return \%out;
}

sub checkify {
    my(@c) = @_;
    my %ret;
    foreach my $c (@c) {
	my $t = $c->{_type};
	my $p = $c->{_port}+0;
	my %c;
	$c{'port'} = $p if $p > 0;
	if($t =~ /^(http|https)$/) {
	    $c{'host'}   = $c->{_host} if defined $c->{_host};
	    $c{'path'}   = $c->{_path} if defined $c->{_path};
	    $c{'method'} = $c->{_meth} if defined $c->{_meth};
	    $c{'expect'} = $c->{_expc}+0 if defined $c->{_expc};
	}
	push @{$ret{$t}}, \%c;
    }
    return \%ret;
}

sub policy {
    my($policy, $defaults) = @_;
    my %p = %$policy;

    
    my @policy;
    
    foreach my $p (sort keys %p) {
	my $v = $p{$p};
	
	$v = {} unless defined $v;
	
	given(ref($v)) {
	    when ('HASH') {}
	    when ('') {
		given ($v) {
		    when (/^[1-9][0-9]*$/) { $v = {'bind' => $v} }
		    default { die "$v" }
		}
	    }
	    default { die ref($v) }
	}
	
	my $port = 0;
	my $type = "tcp";
	
	if($p =~ /^(.*)\*$/) {	    
	    $p = $1;
	    $v->{'checks'} = [];
	}
	
	given ($p) {
	    when (/^[1-9][0-9]*$/)       { $port = $p; $type = "tcp"; }
	    when (m'^([1-9][0-9]*)/udp$') { $port = $1; $type = "udp"; }
	    when (m'^([1-9][0-9]*)/tcp$') { $port = $1; $type = "tcp"; }
	    
	    when (m'^(([1-9][0-9]*)/|)http$')   { $port = $2 eq '' ? 80  : $2+0; $type = "http"; }
	    when (m'^(([1-9][0-9]*)/|)https$')  { $port = $2 eq '' ? 443 : $2+0; $type = "https"; }

	    when ('dns/tcp')  { $port = 53; $type = "dns/tcp"; } # deprecated (/etc/services)
	    when ('dns/udp')  { $port = 53; $type = "dns/udp"; } # deprecated (/etc/services)
	    when ('dns')      { $port = 53; $type = "dns"; }     # deprecated (/etc/services)

	    when ('domain/tcp')  { $port = 53; $type = "dns/tcp"; }
	    when ('domain/udp')  { $port = 53; $type = "dns/udp"; }
	    when ('domain')      { $port = 53; $type = "dns"; }

	    when ('smtp')  { $port = 25; $type = "tcp"; }
	    when ('ssh')   { $port = 22; $type = "tcp"; }
	    when ('telet') { $port = 23; $type = "tcp"; }
	    when ('pop2')  { $port = 109; $type = "tcp"; }
	    when ('pop3')  { $port = 110; $type = "tcp"; }
	    when ('imap')  { $port = 143; $type = "tcp"; }

	    default { die "policy: $p\n" }
	}

	$port = int($port)+0;
	die if $port < 1;
	
	given ($type) {

	    when ('dns') {
		push @policy, checks('dns', 'tcp', $port,  $v, $defaults);
		push @policy, checks('dns', 'udp', $port,  $v, $defaults);
	    }
	
	    
	    when ('dns/tcp') { push @policy, checks('dns', 'tcp', $port,  $v, $defaults) }
	    when ('dns/udp') { push @policy, checks('dns', 'udp', $port,  $v, $defaults) }
	    
	    when ('udp') { push @policy, checks($type, 'udp', $port,  $v, $defaults) }
	    default      { push @policy, checks($type, 'tcp', $port,  $v, $defaults) }
	    
	}
    }

    return @policy;
}

sub checks() {
    my($type, $protocol, $port, $policy, $defaults) = @_;

    my %defaults = %$defaults if defined $defaults;
    
    $defaults{_host} = $policy->{'host'}   if exists $policy->{'host'};
    $defaults{_path} = $policy->{'path'}   if exists $policy->{'path'};
    $defaults{_meth} = $policy->{'method'} if exists $policy->{'method'};
    $defaults{_expc} = $policy->{'expect'} if exists $policy->{'expect'};

    my @checks = @{$policy->{'checks'}} if defined $policy->{'checks'};

    my $chks = !(exists $policy->{'checks'} && scalar(@checks) == 0);
    
    
    return {
	_prot => $protocol,
	_port => $port,
	
	_schd => key($policy, 'scheduler',   $defaults->{_schd}),
	_stic => key($policy, 'sticky',      $defaults->{_stic}),
	_need => key($policy, 'need',        $defaults->{_need}),
	_name => key($policy, 'name',        $defaults->{_name}),
	_desc => key($policy, 'description', $defaults->{_desc}),
	_bind => key($policy, 'bind',        $port)+0,
	
	_chks => $chks ? [ check($protocol, $port, $type, $policy, \%defaults, @checks) ] : [],
    };
}

sub check() {
    my($protocol, $port, $type, $policy, $defaults, @checks) = @_;
    my %d = %$defaults;
    my @c;

    
    if(scalar(@checks) == 0) {
	# defaults
	
	my $http = {
	    _type => $type,
	    _host => $d{_host},
	    _path => $d{_path},
	    _meth => $d{_meth},
	    _expc => $d{_expc},
	    _port => 0,
	};

	given ($type) {
	    when ('http')  { push @c, $http }
	    when ('https') { push @c, $http }
	    when ('dns')   {
		given ($protocol) {
		    when ('udp') { push @c, { _type => 'dns' } }
		    when ('tcp') { push @c, { _type => 'syn' }, { _type => 'dns' } }
		}
	    }
	    when ('tcp') { push @c, { _type => 'syn' } }	    
	    default {
		push @c, {_type => 'syn' } if $protocol eq 'tcp';
	    }
	}
    } else {
	foreach my $c (@checks) {
	    my $default = $type;

	    given($default) {
		when("http") {}
		when("https") {}
		when("dns") {}		
		when("tcp") { $default = "syn" }
		default { next } # eg. no default check for udp
	    }

	    push @c, {
	        _type => key($c, 'type',   $default),
		_host => key($c, 'host',   $d{_host}),
		_path => key($c, 'path',   $d{_path}),
		_meth => key($c, 'method', $d{_meth}),
		_expc => key($c, 'expect', $d{_expc}),
		_port => key($c, 'port',   0)+0,
	    };
	    
	}
    }

    return @c;
}

sub key {
    my($a, $k, $d) = @_;
    return defined $a->{$k} ? $a->{$k} : $d;
}

sub jsonbool {
    my($v) = @_;
    return $v eq 'true' ?  JSON::true : JSON::false;
}

sub yamlbool {
    my($v) = @_;
    return $v =~ /^(true|yes|on)$/i ? JSON::true : JSON::false;
}
