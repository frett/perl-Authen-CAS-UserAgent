package Authen::CAS::UserAgent;

use strict;
use utf8;
use base qw{LWP::UserAgent Exporter};

our $VERSION = 0.900;

use constant CASHANDLERNAME => 'CasLoginHandler';
use constant XMLNS_CAS => 'http://www.yale.edu/tp/cas';

use constant ERROR_PROXY_INVALIDRESPONSE => 1;
use constant ERROR_PROXY_INVALIDTICKET   => 2;
use constant ERROR_PROXY_UNKNOWN         => 3;

our @EXPORT_OK = qw{
	ERROR_PROXY_INVALIDRESPONSE
	ERROR_PROXY_INVALIDTICKET
	ERROR_PROXY_UNKNOWN
};
our %EXPORT_TAGS = (
	ERRORS => [qw{
		ERROR_PROXY_INVALIDRESPONSE
		ERROR_PROXY_INVALIDTICKET
		ERROR_PROXY_UNKNOWN
	}],
);

use HTTP::Request;
use HTTP::Request::Common ();
use HTTP::Status ();
use URI;
use URI::Escape qw{uri_escape};
use URI::QueryParam;
use XML::LibXML;
use XML::LibXML::XPathContext;

##LWP handlers

#cas login handler, detects a redirect to the cas login page, logs the user in and updates the initial redirect
my $casLoginHandler = sub {
	my ($response, $ua, $h) = @_;

	#prevent potential recursion caused by attempting to log the user in
	return if($h->{'running'} > 0);

	#check to see if this is a redirection to the login page
	my $uri = URI->new_abs($response->header('Location'), $response->request->uri)->canonical;
	my $loginUri = URI->new_abs('login', $h->{'casServer'})->canonical;
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

		#get a ticket for the specified service
		my $ticket = $ua->getTicket($service, $h);

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
					my $uri = $response->request->uri;
					my $newUri = URI->new_abs(scalar $response->header('Location'), $uri);

					#check to see if the target uri is the same as the original uri (ignoring the ticket)
					my $targetUri = $newUri->clone;
					if($targetUri =~ s/[\&\?]ticket=[^\&\?]*$//sog) {
						if($targetUri eq $uri) {
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

#default callback to log the user into CAS and return a ticket for the specified service
#TODO: add LT support
my $defaultLoginCallback = sub {
	my ($service, $ua, $h) = @_;

	#issue the login request
	my $loginUri = URI->new_abs('login', $h->{'casServer'});
	my $response = $ua->simple_request(HTTP::Request::Common::POST($loginUri, [
		'service' => $service,
		'username' => $h->{'username'},
		'password' => $h->{'password'},
	]));

	#short-circuit if there is no response from CAS for some reason
	return if(!$response);

	#process all the heuristics until a ticket is found
	my $ticket;
	foreach (@{$h->{'heuristics'}}) {
		#skip invalid heuristics
		next if(ref($_) ne 'CODE');

		#process the current heuristic
		$ticket = eval {$_->($response, $service)};

		#quit processing if a ticket is found
		return $ticket if(defined $ticket);
	}

	#return undefined if no ticket was found
	return;
};

# Login callback when the specified server is in proxy mode
my $proxyLoginCallback = sub {
	my ($service, $ua, $h) = @_;

	#clear any previous error
	delete $h->{'error'};

	#create the request uri
	my $ptUri = URI->new_abs('proxy', $h->{'casServer'});
	$ptUri->query_form(
		'pgt'           => $h->{'pgt'},
		'targetService' => $service,
	);

	# fetch proxy ticket and parse response xml
	my $response = $ua->simple_request(HTTP::Request::Common::GET($ptUri));
	my $doc = eval {XML::LibXML->new()->parse_string($response->decoded_content('charset' => 'none'))};
	if($@ || !$doc) {
		$h->{'error'} = ERROR_PROXY_INVALIDRESPONSE;
		push @{$h->{'errors'}}, $h->{'error'};
		return;
	}

	# process the response to extract the proxy ticket or any errors
	my $xpc = XML::LibXML::XPathContext->new();
	$xpc->registerNs('cas', XMLNS_CAS);
	if($xpc->exists('/cas:serviceResponse/cas:proxyFailure', $doc)) {
		my $code = $xpc->findvalue('/cas:serviceResponse/cas:proxyFailure[position()=1]/@code', $doc);
		if($code eq 'INVALID_TICKET') {
			$h->{'error'} = ERROR_PROXY_INVALIDTICKET;
			push @{$h->{'errors'}}, $h->{'error'};
		}
		else {
			$h->{'error'} = ERROR_PROXY_UNKNOWN;
			push @{$h->{'errors'}}, $h->{'error'};
		}
	}
	elsif($xpc->exists('/cas:serviceResponse/cas:proxySuccess', $doc)) {
		return $xpc->findvalue('/cas:serviceResponse/cas:proxySuccess[position()=1]/cas:proxyTicket[position()=1]', $doc);
	}
	else {
		$h->{'error'} = ERROR_PROXY_INVALIDRESPONSE;
		push @{$h->{'errors'}}, $h->{'error'};
	}

	# default to no ticket being returned
	return;
};

#Login callback for CAS servers that implement the RESTful API
#TODO: cache the TGT
my $restLoginCallback = sub {
	my ($service, $ua, $h) = @_;

	#retrieve the tgt
	my $loginUri = URI->new_abs('v1/tickets', $h->{'casServer'});
	my $tgtResponse = $ua->simple_request(HTTP::Request::Common::POST($loginUri, [
		'username' => $h->{'username'},
		'password' => $h->{'password'},
	]));
	return if($tgtResponse->code != 201);
	my $tgtUri = $tgtResponse->header('Location');

	#retrieve a ticket for the requested service
	my $ticketResponse = $ua->simple_request(HTTP::Request::Common::POST($tgtUri, [
		'service' => $service,
	]));
	return if($ticketResponse->code != 200);
	return $ticketResponse->decoded_content;
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
#	pgt        => the pgt for a proxy login handler
#	proxy      => a boolean indicating this handler is a proxy login handler
#	restful    => a boolean indicating if the CAS server supports the RESTful API
#	callback   => a login callback to use for logging into CAS, it should return a ticket for the specified service
#	heuristics => an array of heuristic callbacks that are performed when searching for the service and ticket in a CAS response
#	strict     => only allow CAS login when the service is the same as the original url
sub attachCasLoginHandler($%) {
	my $self = shift;
	my (%opt) = @_;

	#short-circuit if required options aren't specified
	return if(!exists $opt{'server'});
	return if(!$opt{'proxy'} && !(exists $opt{'username'} && exists $opt{'password'}));
	return if($opt{'proxy'} && !$opt{'pgt'});

	#sanitize options
	$opt{'server'} = URI->new($opt{'server'} . ($opt{'server'} =~ /\/$/o ? '' : '/'))->canonical;
	$opt{'heuristics'} = [$opt{'heuristics'}] if(ref($opt{'heuristics'}) ne 'ARRAY');
	push @{$opt{'heuristics'}}, $defaultHeuristic;
	my $callback =
		ref($opt{'callback'}) eq 'CODE' ? $opt{'callback'}    :
		$opt{'proxy'}                   ? $proxyLoginCallback :
		$opt{'restful'}                 ? $restLoginCallback  :
		$defaultLoginCallback;

	#remove any pre-existing login handler for the current CAS server
	$self->removeCasLoginHandlers($opt{'server'});

	#attach a new CAS login handler
	$self->set_my_handler('response_done', $casLoginHandler,
		'owner' => CASHANDLERNAME,
		'casServer'  => $opt{'server'},
		'username'   => $opt{'username'},
		'password'   => $opt{'password'},
		'pgt'        => $opt{'pgt'},
		'loginCb'    => $callback,
		'heuristics' => $opt{'heuristics'},
		'strict'     => $opt{'strict'},
		'errors'     => [],
		'running'    => 0,
		'm_code' => [
			HTTP::Status::HTTP_MOVED_PERMANENTLY,
			HTTP::Status::HTTP_FOUND,
			HTTP::Status::HTTP_SEE_OTHER,
			HTTP::Status::HTTP_TEMPORARY_REDIRECT,
		],
	);

	return 1;
}

sub getCasLoginHandlers($;$) {
	my $self = shift;
	my ($server) = @_;

	$server = URI->new($server . ($server =~ /\/$/o ? '' : '/'))->canonical if(defined $server);
	return $self->get_my_handler('response_done',
		'owner' => CASHANDLERNAME,
		(defined $server ? ('casServer' => $server) : ()),
	);
}

# method that will retrieve a Ticket for the specified service
sub getTicket($$;$) {
	my $self = shift;
	my ($service, $server) = @_;

	# resolve which handler to use
	my $h;
	if(ref($server) eq 'HASH' && defined $server->{'casServer'}) {
		$h = $server;
	}
	else {
		my @handlers = $self->getCasLoginHandlers($server);
		die 'too many CAS servers found, try specifying a specific CAS server' if(@handlers > 1);
		$h = $handlers[0];
	}
	die 'cannot find a CAS server to fetch the ST from' if(!$h);

	# get a ticket from the handler
	$h->{'running'}++;
	my $ticket = eval {$h->{'loginCb'}->($service, LWP::UserAgent->new(), $h)};
	$h->{'running'}--;

	# return the found ticket
	return $ticket;
}

#method that will remove the cas login handlers for the specified cas servers or all if a specified server is not provided
sub removeCasLoginHandlers($@) {
	my $self = shift;

	#remove cas login handlers for any specified cas servers
	$self->remove_handler('response_done',
		'owner' => CASHANDLERNAME,
		'casServer' => $_,
	) foreach(map {URI->new($_ . ($_ =~ /\/$/o ? '' : '/'))->canonical} @_);

	#remove all cas login handlers if no servers were specified
	$self->remove_handler('response_done',
		'owner' => CASHANDLERNAME,
	) if(!@_);

	return;
}

1;
