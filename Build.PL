#!/usr/bin/perl

use strict;

use Module::Build;

Module::Build->new(
	'module_name'        => 'Authen::CAS::UserAgent',
	'create_makefile_pl' => 'traditional',
	'dist_abstract'      => 'LWP::UserAgent subclass for a CAS aware UserAgent',
	'license'            => 'bsd',
	'configure_requires' => {
		'Module::Build'  => '0.36',
	},
	'requires'           => {
		'Exporter'       => 0,
		'HTTP::Message'  => 0,
		'LWP::UserAgent' => 0,
		'URI'            => 0,
		'XML::LibXML'    => 0,
	},
)->create_build_script();
