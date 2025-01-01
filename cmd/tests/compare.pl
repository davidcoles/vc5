#!/usr/bin/perl
use strict;
use YAML;
use JSON;
use Test::Deep;
use Test::Builder;

my $file = shift or die;

die unless open(JSON, '<', $file);
my $ref = from_json(join('', <JSON>));
my $test = from_json(join('', <STDIN>));

my $Test = Test::Builder->new;
cmp_deeply($ref, $test, $file);
$Test->done_testing();
