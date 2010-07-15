package Authen::CAS::UserAgent;

use strict;
use utf8;
use base qw{LWP::UserAgent};

our $VERSION = 1.044;

use constant CASHANDLERNAME => 'CasLoginHandler';

use HTTP::Request;
use HTTP::Request::Common ();
use HTTP::Status ();
use URI;
use URI::Escape qw{uri_escape};
use URI::QueryParam;

##LWP handlers

#cas login handler, detects a redirect to the cas login page, logs the user in and updates the initial redirect
my $casLoginHandler = sub {
	my ($response, $ua, $h) = @_;

	#prevent potential recursion caused by attempting to log the user in
	return if($h->{'running'});

	#check to see if this is a redirection to the login page
	my $uri = URI->new_abs($response->header('Location'), $response->request->uri);
	my $loginUri = URI->new_abs('login', $h->{'casServer'});
	if(
		$uri->scheme eq $loginUri->scheme &&
		$uri->authority eq $loginUri->authority &&
		$uri->path eq $loginUri->path
	) {
		#short-circuit if a service isn't specified
		my $service = URI->new(scalar $uri->query_param('service'));
		return if($service eq '');

		#short-circuit if in strict mode and the service is different than the original uri
		return if($h->{'strict'} && $response->request->uri ne $service);

		#create a new user agent to segregate CAS cookies from the user agent cookies
		$ua = LWP::UserAgent->new();

		#login to this CAS server, use the running flag to prevent recursion
		$h->{'running'} = 1;
		my $casResponse = eval {
			$ua->simple_request(HTTP::Request::Common::POST($loginUri, [
				'service' => $service,
				'username' => $h->{'username'},
				'password' => $h->{'password'},
			]))
		};
		delete $h->{'running'};

		#short-circuit if there is no response from CAS for some reason
		return if(!$casResponse);

		#process all the heuristics until a ticket is found
		my $ticket;
		foreach (@{$h->{'heuristics'}}) {
			#skip invalid heuristics
			next if(ref($_) ne 'CODE');

			#process the current heuristic
			$ticket = eval {$_->($casResponse, $service)};

			#quit processing if a ticket is found
			last if(defined $ticket);
		}

		#short-circuit if a ticket wasn't found
		return if(!defined $ticket);

		#update the Location header
		$response->header('Location', $service . ($service =~ /\?/o ? '&' : '?') . 'ticket=' . uri_escape($ticket));

		#attach a local response_redirect handler that will issue the redirect if necessary
		push(@{$response->{'handlers'}->{'response_redirect'}},
			{
				%$h,
				'callback' => sub {
					my ($response, $ua, $h) = @_;

					#delete this response_redirect handler from the response object
					delete $response->{'handlers'}->{'response_redirect'};
					delete $response->{'handlers'} unless(%{$response->{'handlers'}});

					#determine the new uri
					my $newUri = URI->new_abs(scalar $response->header('Location'), $response->request->uri);

					#check to see if the target uri is the same as the original uri (ignoring the ticket)
					my $uri = $response->request->uri;
					my $targetUri = $newUri->clone;
					if($targetUri =~ s/[\&\?]ticket=[^\&\?]*$//sog) {
						if($uri eq $targetUri) {
							#clone the original request, update the request uri, and return the new request
							my $request = $response->request->clone;
							$request->uri($newUri);
							return $request
						}
					}

					return;
				},
			},
		);
	}

	return;
};

#default heuristic for detecting the service and ticket in the login response
my $defaultHeuristic = sub {
	my ($response, $service) = @_;

	#attempt using the Location header on a redirect response
	if($response->is_redirect) {
		my $uri = $response->header('Location');
		if($uri =~ /[\?\&]ticket=([^&]*)$/o) {
			return $1;
		}
	}

	#check for a javascript window.location.href redirect
	if($response->decoded_content =~ /window\.location\.href=\"[^\"]*ticket=([^&\"]*?)\"/sog) {
		return $1;
	}

	return;
};

##Static Methods

#return the default user agent for this class
sub _agent($) {
	return
		$_[0]->SUPER::_agent . ' ' .
		'CAS-UserAgent/' . $VERSION;
}

#Constructor
sub new($%) {
	my $self = shift;
	my (%opt) = @_;

	#setup the base object
	$self = $self->SUPER::new(%opt);

	#attach a cas login handler if options were specified
	$self->attachCasLoginHandler(%{$opt{'casOpts'}}) if(ref($opt{'casOpts'}) eq 'HASH');

	#return this object
	return $self;
}

##Instance Methods

#method that will attach the cas server login handler
#	server     => the base CAS server uri to add a login handler for
#	username   => the username to use to login to the specified CAS server
#	password   => the password to use to login to the specified CAS server
#	heuristics => an array of heuristic callbacks that are performed when searching for the service and ticket in a CAS response
#	strict     => only allow CAS login when the service is the same as the original url
sub attachCasLoginHandler($%) {
	my $self = shift;
	my (%opt) = @_;

	#short-circuit if required options aren't specified
	return if(!exists $opt{'username'});
	return if(!exists $opt{'password'});
	return if(!exists $opt{'server'});

	#sanitize options
	$opt{'server'} = URI->new($opt{'server'} . ($opt{'server'} =~ /\/$/o ? '' : '/'));
	$opt{'heuristics'} = [$opt{'heuristics'}] if(ref($opt{'heuristics'}) ne 'ARRAY');
	push @{$opt{'heuristics'}}, $defaultHeuristic;

	#remove any pre-existing login handler for the current CAS server
	$self->removeCasLoginHandlers($opt{'server'});

	#attach a new CAS login handler
	$self->set_my_handler('response_done', $casLoginHandler,
		'owner' => CASHANDLERNAME,
		'casServer'  => $opt{'server'},
		'username'   => $opt{'username'},
		'password'   => $opt{'password'},
		'heuristics' => $opt{'heuristics'},
		'strict'     => $opt{'strict'},
		'm_code' => [
			HTTP::Status::HTTP_MOVED_PERMANENTLY,
			HTTP::Status::HTTP_FOUND,
			HTTP::Status::HTTP_SEE_OTHER,
			HTTP::Status::HTTP_TEMPORARY_REDIRECT,
		],
	);

	return 1;
}

#method that will remove the cas login handlers for the specified cas servers or all if a specified server is not provided
sub removeCasLoginHandlers($@) {
	my $self = shift;

	#remove cas login handlers for any specified cas servers
	$self->remove_handler('response_done',
		'owner' => CASHANDLERNAME,
		'casServer' => $_,
	) foreach(@_);

	#remove all cas login handlers if no servers were specified
	$self->remove_handler('response_done',
		'owner' => CASHANDLERNAME,
	) if(!@_);

	return;
}

1;
