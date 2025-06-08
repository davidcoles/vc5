#!/usr/bin/env perl
use strict;
use YAML;
use JSON;
use Socket;
use Getopt::Std;
use feature qw(switch);
no warnings qw(experimental::smartmatch); 

# This script is designed to take a comapct, human-readable YAML
# configuration file and translate it into a more verbose, explicit
# JSON format that the load balancer daemon can ingest.

my $TRUE  = JSON::true;
my $FALSE = JSON::false;

getopts('nhx', \my %opt);

# -n NAT mode (allow port mappings)
# -x Dump example config on stdout

if($opt{'x'}) {
    print <DATA>;
    exit;
}

my $conf = YAML::Load(join('', <>));
my $json = {};

my $policy = $conf->{'policy'};
my $servers = $conf->{'servers'};
my $services = $conf->{'services'};
my %defaults;

my $scheduler = $conf->{'scheduler'} if exists $conf->{'scheduler'};

$json->{'services'} = services($scheduler, $services, \%defaults, $servers, $policy);
$json->{'bgp'} = new_rhi($conf->{'bgp'}, $conf->{'prefixes'});
$conf->{'learn'}+=0 if defined $conf->{'learn'};

foreach(qw(vlans vlans6 multicast webserver webroot defcon logging address interfaces native untagged host_id)) {
    $json->{$_} = $conf->{$_} if exists $conf->{$_};
}

if(defined $conf->{'native'}) {
    $json->{'native'} = jsonbool($conf->{'native'});
}

if(defined $conf->{'untagged'}) {
    $json->{'untagged'} = jsonbool($conf->{'untagged'});
}

if(defined $conf->{'bgp'} && jsonbool($conf->{'bgp'}->{'listen'})) {
    $json->{'listen'} = $TRUE;
}

if(defined $conf->{'bgp'} && $conf->{'bgp'}->{'learn'} > 0) {
    $json->{'learn'} = $conf->{'bgp'}->{'learn'} + 0;
}

if(defined $json->{'logging'}) {
    $json->{'logging'}->{'alert'}+=0;

#    if(defined $json->{'logging'}->{'elasticsearch'}) {
#	my $val = jsonbool($json->{'logging'}->{'elasticsearch'}->{'data_stream'});
#	$json->{'logging'}->{'elasticsearch'}->{'data_stream'} = $val;
 #   }
}

if(defined $json->{'logging'}) {
    $json->{'logging'}->{'syslog'} = jsonbool($json->{'logging'}->{'syslog'});
}

if(defined $json->{'defcon'}) {
    $json->{'defcon'}+=0;
    given($json->{'defcon'}) {
	when(1) {}
	when(2) {}
	when(3) {}
	when(4) {}
	when(5) {}
	default { die "defcon setting needs to be between an integer between 1 and 5"; }
    }
}

print to_json($json, {pretty => 1, canonical => 1});

exit;

sub services {
    my($scheduler, $services, $defaults, $servers, $policy) = @_;
    my %defaults = %$defaults;
    my %out;

    my %disabled;
    
    foreach my $s (@$services) {

	$defaults{_host} = key($s, 'host',        undef); # checks
	$defaults{_path} = key($s, 'path',        undef); # checks
	$defaults{_meth} = key($s, 'method',      undef); # checks
	$defaults{_expc} = key($s, 'expect',      undef); # checks
	$defaults{_name} = key($s, 'name',        undef);
	$defaults{_desc} = key($s, 'description', undef);
	$defaults{_prio} = key($s, 'priority',    undef);
	$defaults{_need} = key($s, 'need',        1)+0;
	$defaults{_stic} = key($s, 'sticky',      JSON::false);
	$defaults{_rest} = key($s, 'reset',       JSON::false);
	$defaults{_schd} = key($s, 'scheduler',   $scheduler);
	$defaults{_pers} = key($s, 'persist',     undef);	
	
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
	    when('')  {
		my $n = $s->{'servers'};
		die "Server list '$n' does not exist\n" unless exists $servers->{$n};
		@servers = @{$servers->{$n}};
		
	    }
	    default { die }
	}
	
	given(ref($s->{'policy'})) {
	    when('HASH') { %policy = %{$s->{'policy'}} }
	    when('')  {
		my $n = $s->{'policy'};
		die "Policy '$n' does not exist\n" unless exists $policy->{$n};
		%policy = %{$policy->{$n}};
	    }
	    default { die }
	}

	my %servers;
	foreach(@servers) {
	    die "bad server: $_\n" unless /^(\d+\.\d+\.\d+\.\d+)(\*|)$/;
	    $servers{$1} = {_dsbl => $2 eq '' ? 0 : 1};
	}
	
	my @policy = policy(\%policy, \%defaults);

	foreach my $v (@virtual) {

	    if($v =~ /^(.*)\*$/) {
		$v = $1;
		$disabled{$v} = 1;
	    }
	    
	    foreach my $p (@policy) {
		my $l4 = $p->{_prot} . ':' . $p->{_port};
		my @p = %$p;

		my $svc = { 'need' => $p->{_need}+0 };

		$svc->{'name'}        = $p->{_name} if defined $p->{_name};
		$svc->{'description'} = $p->{_desc} if defined $p->{_desc};
		$svc->{'priority'}    = $p->{_prio} if defined $p->{_prio};
		$svc->{'scheduler'}   = $p->{_schd} if defined $p->{_schd};
		$svc->{'persist'}     = $p->{_pers}+0 if defined $p->{_pers};
		$svc->{'sticky'}      = jsonbool($p->{_stic}) if defined $p->{_stic};
		$svc->{'reset'}       = jsonbool($p->{_rest}) if defined $p->{_rest};

		my %rips;

		my $checks = checklist(@{$p->{_chks}});
		my $bind =  $p->{_bind}+0;

		if($bind != 0 && $bind < 1 || $bind > 65535) {
		    die "bind: $bind\n";
		}

		if(!defined $opt{'n'} && $bind != $p->{_port}) {
		    die "port mismatch! enable port mapping for non DSR with -n";
		}

		if(defined $svc->{'priority'} && $svc->{'priority'} !~ /^(critical|high|medium|low)$/) {
		    die "Invalid priority: ".$svc->{'priority'}."\n";
		}
		
		foreach my $s (sort keys %servers) {
		    $rips{$s.":$bind"} = {
			'checks'   => $checks,
			'disabled' => $servers{$s}->{_dsbl} ? JSON::true : JSON::false,
		        'weight' => $servers{$s}->{_dsbl} ? 0 : 1,
		    }
		}

		$svc->{'reals'} = \%rips;
		
		$out{$v.":".$p->{_port}.":".$p->{_prot}} = $svc;
	    }
	}
    }

    foreach(keys %out) {
	$out{$_}->{'disabled'} = $TRUE if /^([^:]+):/ && $disabled{$1};
    }
    
    return \%out;
}

sub checklist {
    my(@c) = @_;
    my @ret;
    foreach my $c (@c) {
	my $t = $c->{_type};
	my $p = $c->{_port}+0;
	my %c;

	$c{'type'} = $t;
	$c{'port'} = $p if $p > 0;

	given($t) {
	    when('dns') {
		#if($opt{m}) {
		    $c{'method'} = $c->{_meth} if defined $c->{_meth};
		#} else  {
		#    $c{'method'} = $c->{_meth} eq "tcp" ? $TRUE : $FALSE if defined $c->{_meth};
		#}
	    }

	    when(/^(http|https)$/) {
		$c{'host'}   = $c->{_host} if defined $c->{_host};
		$c{'path'}   = $c->{_path} if defined $c->{_path};
		$c{'expect'} = expect($c->{_expc}) if defined $c->{_expc};
		#if($opt{m})	{
		    $c{'method'} = $c->{_meth} if defined $c->{_meth};
		#} else {
		#    $c{'method'} = $c->{_meth} eq "HEAD" ? $TRUE : $FALSE if defined $c->{_meth};
		#}
	    }
	}
	
	push @ret, \%c;
    }
    
    return [ @ret ];
}

sub expect {
    my($expect) = @_;
    my @expect;

    return [ 0 ] if $expect eq 'any';
    
    foreach (split(/\s+/, $expect)) {
	my @val;
	
	if(/([1-9][0-9][0-9])-([1-9][0-9][0-9])$/) {
	    if($1 > $2) {
		@val = $2..$1;
	    } else {
		@val = $1..$2;
	    }
	} else {
	    die unless /^[1-9][0-9][0-9]$/;
	    @val = ($_+0);
	}

	push @expect, @val;
    }
    
    return [ @expect ];
}

sub policy {
    my($policy, $defaults) = @_;
    my @policy;
    my %policy = %$policy;
    
    foreach my $p (sort keys %policy) {
	my $v = $policy{$p};
	$v = {} unless defined $v; # policy may be void - eg. all defaults
	
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
	
	my $def = 1;
	my $tcp = 1;
	my $port = 0;
	my $type = "none";
	
	if($p =~ /^(.*)\*$/) {	    
	    $p = $1;
	    $v->{'checks'} = [];
	    $def = 0;
	}
	
	given ($p) {
	    when (/^[1-9][0-9]*$/)        { $port = $p; $type = "syn"; }
	    when (m'^([1-9][0-9]*)/tcp$') { $port = $1; $type = "syn"; }
	    when (m'^([1-9][0-9]*)/udp$') { $port = $1; $tcp = 0; }
	    
	    when (m'^(([1-9][0-9]*)/|)http$')   { $port = $2 eq '' ? 80  : $2+0; $type = "http"; }
	    when (m'^(([1-9][0-9]*)/|)https$')  { $port = $2 eq '' ? 443 : $2+0; $type = "https"; }
	    when (m'^(([1-9][0-9]*)/|)domain$') { $port = $2 eq '' ? 53 :  $2+0; $type = "domain"; }
	    
	    when ('domain/tcp')  { $port = 53; $type = "dns"; $tcp = 1 }
	    when ('domain/udp')  { $port = 53; $type = "dns"; $tcp = 0 }
	    
	    when ('ftp')    { $port = 21;  $type = "syn"; }
	    when ('smtp')   { $port = 25;  $type = "syn"; }
	    when ('ssh')    { $port = 22;  $type = "syn"; }
	    when ('telnet') { $port = 23;  $type = "syn"; }
	    when ('pop2')   { $port = 109; $type = "syn"; }
	    when ('pop3')   { $port = 110; $type = "syn"; }
	    when ('imap')   { $port = 143; $type = "syn"; }
	    when ('imaps')  { $port = 993; $type = "syn"; }

	    default { die "policy: $p\n" }
	}

	$port = int($port)+0;
	die "port: $port\n" if $port < 1 || $port > 65535;

	$type = "none" if !$def;

	given ($type) {
	    when ("domain") {
		push @policy, service('dns', 1, $port,  $v, $defaults);
		push @policy, service('dns', 0, $port,  $v, $defaults);
	    }
	    
	    default { push @policy, service($type, $tcp, $port,  $v, $defaults) }
	}
    }

    return @policy;
}

sub service() {
    my($type, $tcp, $port, $policy, $defaults) = @_;
    my $protocol = $tcp ? "tcp" : "udp";

    my %defaults = %$defaults if defined $defaults; # SUSPECT
    
    $defaults{_host} = $policy->{'host'}   if exists $policy->{'host'};
    $defaults{_path} = $policy->{'path'}   if exists $policy->{'path'};
    $defaults{_meth} = $policy->{'method'} if exists $policy->{'method'};
    $defaults{_expc} = $policy->{'expect'} if exists $policy->{'expect'};

    my @checks = @{$policy->{'checks'}} if defined $policy->{'checks'}; # SUSPECT
    
    return {
	_prot => $protocol,
	_port => $port,
	
	_pers => key($policy, 'persist',     $defaults->{_pers}),
	_schd => key($policy, 'scheduler',   $defaults->{_schd}),
	_stic => key($policy, 'sticky',      $defaults->{_stic}),
	_rest => key($policy, 'reset',       $defaults->{_rest}),
	_need => key($policy, 'need',        $defaults->{_need}),
	_name => key($policy, 'name',        $defaults->{_name}),
	_desc => key($policy, 'description', $defaults->{_desc}),
	_prio => key($policy, 'priority',    $defaults->{_prio}),
	_bind => key($policy, 'bind',        $port)+0,
	_chks => [ checks($tcp, $port, $type, $policy, \%defaults, @checks) ],
    };
}

sub checks() {
    my($tcp, $port, $type, $policy, $defaults, @checks) = @_;
    my %d = %$defaults;
    my @c;

    if(scalar(@checks) == 0) {
	given ($type) {
	    when ('none') { }
	    when (/^http|htts$/)  {
		push @c, {
		    _type => $type,
		    _host => $d{_host},
		    _path => $d{_path},
		    _meth => $d{_meth},
		    _expc => $d{_expc},
		};
	    }
	    
	    when('dns') {
		my $meth = $d{_meth};
		$meth = $defaults->{_meth} if !defined $meth && defined $defaults->{_meth};
		$meth = $tcp ? "tcp" : "udp" if (!defined $meth || $meth !~ /^(tcp|udp)$/i );
		
		push @c, {
		    _type => $type,
		    _meth => $meth,
		};
	    }
	    
	    when ('syn')   { push @c, { _type => $type } }

	    default { die "$type\n" } 
	}
    } else {
	foreach my $c (@checks) {
	    my $type = $c->{"type"};
	    my $port = key($c, 'port',   0)+0;
	    
	    given ($type) {
		when (/^http|htts$/)  {
		    push @c, {
			_type => $type,
			_host => key($c, 'host',   $d{_host}),
			_path => key($c, 'path',   $d{_path}),
			_meth => key($c, 'method', $d{_meth}),
			_expc => key($c, 'expect', $d{_expc}),
			_port => $port,
		    };
		}
		
		when ('dns') {
		    my $meth = $c->{"method"};
		    $meth = $defaults->{_meth} if !defined $meth && defined $defaults->{_meth};
		    $meth = undef unless $meth =~ /^(tcp|udp)$/;
		    $meth = $tcp ? "tcp" : "udp" unless defined $meth;
		    push @c, {
			_type => $type,
			_meth => $meth,
			_port => $port,
		    };
		}
		
		when ('syn') { push @c, { _type => $type, _port => $port  } }

		default { die "$type\n" } 		
	    }
	}
    }
    
    return @c;
}

sub key {
    my($a, $k, $d) = @_;

    my $ret = defined $a->{$k} ? $a->{$k} : $d;

    return undef unless defined $ret;

    die "Name '$ret' isn't valid\n" if $k eq 'name' && $ret !~ /^[a-z0-9][-a-z0-9]*$/i;
    #die "Expect '$ret' isn't valid\n" if $k eq 'expect' && $ret !~ /^[1-9][0-9][0-9]$/;
    die "Method '$ret' isn't valid\n" if $k eq 'method' && $ret !~ /^(HEAD|GET)$/;        
    
    return $ret;
}

sub jsonbool {
    my($v) = @_;
    return $v eq 'true' ?  JSON::true : JSON::false;
}

sub yamlbool {
    my($v) = @_;
    return $v =~ /^(true|yes|on)$/i ? JSON::true : JSON::false;
}


######################################################################

sub filter {
    my($m, $n) = @_;
    return "0.0.0.0/0" if $n eq 'any';
    return $n unless defined $m && exists $m->{$n};
    return @{$m->{$n}};
}


sub new_rhi {
    my($rhi, $map) = @_;

    my $default = params($rhi);
    my %peers = map { $_ => $default } @{$rhi->{'peers'}} if defined $rhi->{'peers'}; # SUSPECT
    

    if(defined $rhi->{'groups'}) {
	foreach my $g (@{$rhi->{'groups'}}) {
	    #my @accept = map { filter($map, $_) } @{$g->{'accept'}} if defined $g->{'accept'};
	    #my @reject = map { filter($map, $_) } @{$g->{'reject'}} if defined $g->{'reject'};
	    my @accept;
	    my @reject;
	    @accept = map { filter($map, $_) } @{$g->{'accept'}} if defined $g->{'accept'};
	    @reject = map { filter($map, $_) } @{$g->{'reject'}} if defined $g->{'reject'};
	    
	    my $d = params($g, %$default);
	    
	    if(defined $g->{'peers'}) {
		foreach my $p (@{$g->{'peers'}}) {
		    die "ASN not set for $p\n" unless $d->{'as_number'} > 0;
		    $d->{'accept'} = \@accept;
		    $d->{'reject'} = \@reject;
		    $peers{$p} = $d;
		}
	    }
	}
    }

    return \%peers;
}

sub params {
    my($o, %p) = @_;
    
    $p{'communities'} = $o->{'communities'} if defined $o->{'communities'};    
    $p{'source_ip'} = $o->{'source_ip'} if defined $o->{'source_ip'};
    $p{'as_number'} = $o->{'as_number'}+0 if defined $o->{'as_number'};
    $p{'hold_time'} = $o->{'hold_time'}+0 if defined $o->{'hold_time'};
    $p{'local_pref'} = $o->{'local_pref'}+0 if defined $o->{'local_pref'};
    $p{'med'} = $o->{'med'}+0 if defined $o->{'med'};
    $p{'multiprotocol'} = $TRUE;
    $p{'next_hop_6'} = "fd6e:eec8:76ac:ac1d:100::7";
    return \%p;
}


__END__;
---

#webserver: :80
#webroot: /var/local/vc5
#multicast: 224.0.0.1:12345

#native: false
#untagged: false
#address: 10.1.10.100 # load balancer server's primary ip
#interfaces:
#  - ens192
#  - ens224
    
bgp:
  as_number: 65000
  peers:
    - 10.1.10.200
    - 10.1.10.201    

# If Teams or Slack webhook URLs are set then messages of level <alert> (default 0) or lower wil be sent to the channel.
# If elasticsearch/index is set then all logs will be written to elasticsearch
# Other setting are optional, and the usual Elasticsearch environment variables will be consulted by the library
    
#logging:
#  #alert: 4 # 0:EMERG, 1:ALERT, 2:CRIT, 3:ERR, 4:WARNING, 5:NOTICE, 6:INFO, 7:DEBUG
#  #teams: https://myorganisation.webhook.office.com/webhookb2/....
#  #slack: https://hooks.slack.com/services/....
#  elasticsearch:
#    index: vc5
#    #addresses:
#    #  - http://10.1.2.31/    
#    #  - http://10.1.2.32/    
#    #username: elastic
#    #password: Xg5nRkc9RA3hALMiBw8X
    
#vlans:
#  10: 10.1.10.0/24
#  20: 10.1.20.0/24
#  30: 10.1.30.0/24    
#  40: 10.1.40.0/24
    
services:
  
  - name: nginx
    virtual:
      - 192.168.101.1
    servers:
      - 10.1.10.10
      - 10.1.10.11
      - 10.1.10.12
      - 10.1.10.13            
    need: 1
    path: /alive
    policy:
      http:
        
#  - name: bind
#    description: DNS servers on a different VLAN
#    virtual:
#      - 192.168.101.2
#    servers:
#      - 10.1.20.10
#      - 10.1.20.12
#      - 10.1.20.13
#      - 10.1.20.14
#    policy:
#      domain:
