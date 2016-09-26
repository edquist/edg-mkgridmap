#!/usr/bin/perl

use strict;
use URI;

#=============================================================================#

package URI::ldaps;

require URI::ldap;
use vars qw(@ISA);

@ISA = qw(URI::ldap);

#-----------------------------------------------------------------------------#

sub default_port { 636 }

#=============================================================================#

package URI::voms;

require URI::http;
use vars qw(@ISA);

@ISA = qw(URI::http);

#-----------------------------------------------------------------------------#

sub default_port { 80 }

#=============================================================================#

package URI::vomss;

use vars qw(@ISA);

@ISA = qw(URI::voms);

#-----------------------------------------------------------------------------#

sub default_port { 443 }

#=============================================================================#

package main;

use Getopt::Long;
use File::Copy;
use Term::ReadKey;
use Net::LDAP;
use Net::LDAP::Util qw(ldap_error_desc);
use Net::LDAPS;
use LWP::UserAgent;
use XML::DOM;
use XML::Parser;
use Sys::Syslog qw(:DEFAULT setlogsock);
use IO::Socket::SSL;

#=============================================================================#

my $opt_conf;
my $opt_proxy;
my $opt_help;
my $opt_output;
my $opt_quiet;
my $opt_safe;
my $opt_verbose;
my $opt_version;
my $opt_cache;
my $opt_usermode;
my $version;
my $localstatedir;
my $gridmap;
my $get_user;
my $default_lcluser;
my $group;
my $auth;
my $gmf_local;
my $timeout;
my $passphrase;
my @GROUP;
my @AUTH;
my @GMF_LOCAL;
my @ACL;
my @RULE;
my %GRID_USER;
my %AUTH_USER;
my %ERRORCODE;
my %STATUS;
my %FLAG;
my %OLD_GRP;

#-----------------------------------------------------------------------------#

sub writeWarnLog($)
  {
    my ($message) = @_;

    (!$opt_quiet && $opt_verbose && $message) || return;

    print STDERR $message;
  }

#-----------------------------------------------------------------------------#

sub writeErrLog($)
  {
    my ($message) = @_;

    (!$opt_quiet && $message) || return;

    print STDERR $message;
  }

#-----------------------------------------------------------------------------#

sub writeSysLog($$)
  {
    my ($level, $message) = @_;

    my @Level;

    @Level = ('warning',
	      'info');

    if ((grep /$level$/, @Level) && $message)
      {
	setlogsock('unix');
	openlog('edg-mkgridmap', 'pid', 'user');
	syslog($level, $message);
	closelog;
      }
  }

#-----------------------------------------------------------------------------#

sub setStatus($)
  {
    my ($condition) = @_;

    $condition || return;

    if (exists $ERRORCODE{$condition})
      {
	$STATUS{$condition} = $ERRORCODE{$condition};
      }
    else
      {
	$FLAG{$condition} = 1;
      }
  }

#-----------------------------------------------------------------------------#

sub exitHandling()
  {
    my $exit_code;
    my $condition;
    my $error_mesg;
    my $grp;

    $exit_code = 0;
    foreach $condition (keys %STATUS)
      {
	$exit_code += $STATUS{$condition};
      }

    foreach $grp (keys %FLAG)
      {
	$exit_code += $FLAG{$grp};
      }

    if ($exit_code != 0)
      {
	$error_mesg = "Exit with error(s) (code=$exit_code)";

	writeSysLog('warning', $error_mesg);
	writeErrLog("$error_mesg\n");
      }

    exit($exit_code);
  }

#-----------------------------------------------------------------------------#

sub getPassPhrase()
  {
    while ($passphrase eq '')
      {
	print STDERR "Enter PEM pass phrase: ";

	ReadMode 2;
	chomp($passphrase = ReadLine 0);
	ReadMode 0;

	print STDERR "\n";
      }

    return $passphrase;
  }

#-----------------------------------------------------------------------------#

sub checkAuth($)
  {
    my ($subject) = @_;

    return 1 unless (@AUTH);

    return 1 if (exists $STATUS{'auth'} && $opt_safe);

    if (! exists $AUTH_USER{$subject})
      {
	writeWarnLog("\"$subject\" not authorized\n");
	return 0;
      }
    else
      {
	writeWarnLog("\"$subject\" authorized\n");
	return 1;
      }
  }

#-----------------------------------------------------------------------------#

sub checkSubject($)
  {
    my ($subject) = @_;

    my $acl;
    my $action;
    my $expr;
    my $i;

    foreach $i (0 .. $#RULE)
      {
	$acl    = $ACL[$i];
	$action = $RULE[$i][0];
	$expr   = $RULE[$i][1];

	if ($subject =~ /^$expr$/i)
	  {
	    if ($action eq 'deny')
	      {
		writeWarnLog("\"$subject\" denied by rule '@$acl'\n");
		return 0;
	      }
	    elsif ($action eq 'allow')
	      {
		writeWarnLog("\"$subject\" allowed by rule '@$acl'\n");
		return 1;
	      }
	  }
      }
  }

#-----------------------------------------------------------------------------#

sub addAuthUser($)
  {
    my $subject = ${shift()};

    if (exists $AUTH_USER{$subject})
      {
	writeWarnLog("\"$subject\" already authorized\n");
      }
    elsif (checkSubject($subject))
      {
	writeWarnLog("\"$subject\" authorized\n");
	$AUTH_USER{$subject} = undef;
      }
  }

#-----------------------------------------------------------------------------#

sub addGridUser($$$)
  {
    my $uri     = ${shift()};
    my $subject = ${shift()};
    my $lcluser = ${shift()};

    if ($subject =~ /"|\\$/)
      {
	writeErrLog(
	  "skipping DN with embedded quoting character '$subject'\n\n");
	setStatus('group');
	return;
      }

    if ($lcluser eq 'AUTO')
      {
	$lcluser = undef;

	$SIG{ALRM} = sub { die };
	eval
	  {
	    alarm 5;
	    chomp($lcluser = `$get_user \"$subject\" 2> /dev/null`);
	    alarm 0;
	  };
      }

    if ($lcluser)
      {
	#
	# allow pool accounts to be overridden by special accounts
	#

	if (exists $GRID_USER{$subject} &&
	    ($GRID_USER{$subject} !~ /^\./ || $lcluser =~ /^\./))
	  {
	    writeWarnLog("\"$subject\" already allowed\n");
	  }
	elsif ((!($uri->scheme =~ /^ldaps?$/) || checkAuth($subject)) &&
	       checkSubject($subject))
	  {
	    $GRID_USER{$subject} = $lcluser;
	  }
      }
    else
      {
	writeWarnLog("\"$subject\" denied: Empty username\n");
      }
  }

#-----------------------------------------------------------------------------#

sub setEnv::ssl()
  {
    if ($opt_usermode)
      {
	my $user_proxy = $ENV{X509_USER_PROXY} || "/tmp/x509up_u$<";

	$ENV{HTTPS_CERT_FILE} = $user_proxy;
	$ENV{HTTPS_KEY_FILE}  = $user_proxy;
	$ENV{HTTPS_CA_FILE}   = $user_proxy if $IO::Socket::SSL::VERSION < '1.88';
      }
    elsif ($<)
      {
	$ENV{HTTPS_CERT_FILE} = $ENV{X509_USER_CERT} ||
	  $ENV{HOME}.'/.globus/usercert.pem';
	$ENV{HTTPS_KEY_FILE}  = $ENV{X509_USER_KEY}  ||
	  $ENV{HOME}.'/.globus/userkey.pem';
      }
    else
      {
	$ENV{HTTPS_CERT_FILE} = $ENV{X509_USER_CERT} ||
	  '/etc/grid-security/hostcert.pem';
	$ENV{HTTPS_KEY_FILE}  = $ENV{X509_USER_KEY}  ||
	  '/etc/grid-security/hostkey.pem';
      }

    $ENV{HTTPS_CA_DIR} = $ENV{CERTDIR} || $ENV{X509_CERT_DIR} ||
      '/etc/grid-security/certificates';
  }

#-----------------------------------------------------------------------------#

sub setEnv::ldaps()
  {
    setEnv::ssl;
  }

#-----------------------------------------------------------------------------#

sub setEnv::http()
  {
    if ($opt_proxy)
      {
	if ($ENV{http_proxy} && !($ENV{http_proxy} =~ /^http:\/\//i))
	  {
	    $ENV{http_proxy} =~ s/^.*:\/\///g;
	    $ENV{http_proxy} = 'http://'.$ENV{http_proxy};
	  }
      }
  }

#-----------------------------------------------------------------------------#

sub setEnv::https()
  {
    setEnv::ssl;

    if ($opt_proxy)
      {
	if ($ENV{https_proxy} && !($ENV{https_proxy} =~ /^http:\/\//i))
	  {
	    $ENV{https_proxy} =~ s/^.*:\/\///g;
	    $ENV{https_proxy} = 'http://'.$ENV{https_proxy};
	  }
      }
    else
      {
	$ENV{https_proxy} = undef;
      }

    $ENV{HTTPS_PROXY}   = undef;
    $ENV{HTTPS_VERSION} = 23;
  }

#-----------------------------------------------------------------------------#

sub setEnv::voms()
  {
    setEnv::http;
  }

#-----------------------------------------------------------------------------#

sub setEnv::vomss()
  {
    setEnv::https;
  }

#-----------------------------------------------------------------------------#

sub getSubject::http($)
  {
    my $uri = ${shift()};

    my $scheme;
    my $io_socket_ssl_version;
    my $parser;
    my $doc;
    my $table;
    my $tr;
    my $td;
    my $i;
    my $j;
    my $attr;
    my $attr_num;
    my $k;
    my $ua;
    my $res;
    my $subject;
    my $error_mesg;
    my $code;
    my @Subject;
    my %ID;

    $code = 0;
    @Subject = ();
    %ID = ();

    $scheme = $uri->scheme;

    $parser = new XML::DOM::Parser;

    if ($scheme eq 'http')
      {
 	setEnv::http;
      }
    elsif ($scheme eq 'https')
      {
	setEnv::https;

	if ($IO::Socket::SSL::VERSION)
	  {
	    $io_socket_ssl_version = $IO::Socket::SSL::VERSION;
	    $IO::Socket::SSL::VERSION = undef;
	  }
      }

    $ua = LWP::UserAgent->new(agent    => "edg-mkgridmap/$version",
                              timeout  => $timeout,
                              ssl_opts => {
                                SSL_cert_file => $ENV{HTTPS_CERT_FILE},
                                SSL_key_file  => $ENV{HTTPS_KEY_FILE}
                              }
    );

    if ($opt_proxy)
      {
	if (($scheme eq 'http') && $ENV{http_proxy})
	  {
	    $ua->proxy('http', $ENV{http_proxy});
	    writeWarnLog("Using proxy server $ENV{http_proxy}\n");
	  }
	elsif (($scheme eq 'https') && $ENV{https_proxy})
	  {
	    writeWarnLog("Using proxy server $ENV{https_proxy}\n");
	  }
      }

    $res = $ua->get($uri,
                    'Cache-Control' => 'no-cache',
                    'Pragma'        => 'no-cache');

    if (defined $io_socket_ssl_version)
      {
	$IO::Socket::SSL::VERSION = $io_socket_ssl_version;
      }

    unless ($res->is_success)
      {
	$error_mesg = "http search($uri): ".(split(/\n/, $res->message))[0];

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    $attr_num = $res->header('Attribute-Num') || 0;

    for ($k = 0; $k < $attr_num; $k++)
      {
	$attr = $res->header("Attribute-$k");
	$ID{$attr} = $k;
      }

    unless ($res->content && ($attr_num > 0) && exists $ID{subject})
      {
	$error_mesg = "http search($uri): No data";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    eval
      {
        $doc = $parser->parse($res->content, ProtocolEncoding => 'ISO-8859-1');
      };

    unless ($doc)
      {
	$error_mesg = "http search($uri): Unknown data format";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    $table = $doc->getElementsByTagName('table');

    if ($table->getLength == 1)
      {
	$code = 1;

	$tr = $table->item(0)->getElementsByTagName('tr');

	for ($i = 0; $i < $tr->getLength; $i++)
	  {
	    $td = $tr->item($i)->getElementsByTagName('td');

	    $j = $ID{subject};

	    if ($td->getLength > $j)
	      {
		$subject = $td->item($j)->getFirstChild->getNodeValue;
		$subject =~ s/[\n\r]//g;
		push (@Subject, $subject);
	      }
	  }
      }
    else
      {
	$error_mesg = "http search($uri): No such object";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    $doc->dispose;

    return ($code, \@Subject);
  }

#-----------------------------------------------------------------------------#

sub getSubject::voms($)
  {
    my $uri = ${shift()}->clone;

    my $scheme;
    my $io_socket_ssl_version;
    my $parser;
    my $doc;
    my $groupname;
    my $retval;
    my $user;
    my $ua;
    my $res;
    my $subject;
    my $error_mesg;
    my $code;
    my @Subject;

    $code = 0;
    @Subject = ();

    $scheme = $uri->scheme;

    $parser = new XML::DOM::Parser;

    if ($scheme eq 'voms')
      {
	setEnv::voms;
      }
    elsif ($scheme eq 'vomss')
      {
	setEnv::vomss;

	if ($IO::Socket::SSL::VERSION)
	  {
	    $io_socket_ssl_version = $IO::Socket::SSL::VERSION;
	    $IO::Socket::SSL::VERSION = undef;
	  }
      }

    $scheme =~ s/^voms/http/;
    $uri->scheme($scheme);

    $uri->path($uri->path.'/services/VOMSCompatibility');
    if ($groupname = $uri->query())
      {
        $uri->query_form(method    => 'getGridmapUsers',
                         container => $groupname);
      }
    else
      {
        $uri->query_form(method => 'getGridmapUsers');
      }

    $ua = LWP::UserAgent->new(agent    => "edg-mkgridmap/$version",
                              timeout  => $timeout,
                              ssl_opts => {
                                SSL_cert_file => $ENV{HTTPS_CERT_FILE},
                                SSL_key_file  => $ENV{HTTPS_KEY_FILE}
                              }
    );

    if ($opt_proxy)
      {
	if (($scheme eq 'http') && $ENV{http_proxy})
	  {
	    $ua->proxy('http', $ENV{http_proxy});
	    writeWarnLog("Using proxy server $ENV{http_proxy}\n");
	  }
	elsif (($scheme eq 'https') && $ENV{https_proxy})
	  {
	    writeWarnLog("Using proxy server $ENV{https_proxy}\n");
	  }
      }

    $res = $ua->get($uri,
                    'Cache-Control' => 'no-cache',
                    'Pragma'        => 'no-cache');

    if (defined $io_socket_ssl_version)
      {
	$IO::Socket::SSL::VERSION = $io_socket_ssl_version;
      }

    unless ($res->is_success)
      {
	$error_mesg = "voms search($uri): ".(split(/\n/, $res->message))[0];

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    eval
      {
        $doc = $parser->parse($res->content, ProtocolEncoding => 'ISO-8859-1');
      };

    unless ($doc)
      {
	$error_mesg = "voms search($uri): Unknown data format";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    $retval = $doc->getElementsByTagName('soapenv:Body');

    if ($retval->getLength == 1)
      {
	$code = 1;

	my $returnNode =
	  $doc->getElementsByTagName('getGridmapUsersReturn')->item(0);

	my @snList = $returnNode->getChildNodes;

	for my $sn (@snList)
	  {
	    if ($sn->getNodeTypeName eq "ELEMENT_NODE" && $sn->getFirstChild)
	      {
		$subject = $sn->getFirstChild->getData;
		push(@Subject, $subject);
	      }
	  }
      }
    else
      {
	$error_mesg = "voms search($uri): No such object";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return ($code, \@Subject);
      }

    $doc->dispose;

    return ($code, \@Subject);
  }

#-----------------------------------------------------------------------------#

sub authSearch::ldap($)
  {
    my $uri = ${shift()};

    my $scheme;
    my $host;
    my $port;
    my $base;
    my $scope;
    my $filter;
    my $ldap;
    my $mesg;
    my $entry;
    my $subject;
    my $error_mesg;
    my @Description;

    $scheme = $uri->scheme;
    $host   = $uri->host;
    $port   = $uri->port;
    $base   = $uri->dn;
    $scope  = $uri->_scope || 'one';
    $filter = $uri->_filter || '(description=subject=*)';

    if ($scheme eq 'ldap')
      {
	$ldap = Net::LDAP->new($host,
			       port    => $port,
			       timeout => $timeout,
			       onerror => undef
			      );
      }
    elsif ($scheme eq 'ldaps')
      {
	setEnv::ldaps;

	$ldap = Net::LDAPS->new($host,
				port       => $port,
				timeout    => $timeout,
				version    => '3',
				verify     => 'require',
				ciphers    => 'HIGH:MEDIUM',
				clientcert => $ENV{HTTPS_CERT_FILE},
				clientkey  => $ENV{HTTPS_KEY_FILE},
				capath     => $ENV{HTTPS_CA_DIR},
				decryptkey => \&getPassPhrase,
				onerror    => undef
			       );
      }

    unless ($ldap)
      {
	$error_mesg = "ldap search($uri): Connection failed";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('auth');
	return;
      }

    $SIG{ALRM} = sub { die };
    eval
      {
	alarm $timeout;
	$mesg = $ldap->bind;
	alarm 0;
      };

    unless ($mesg)
      {
	$error_mesg = "ldap search($uri): bind: Timeout";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('auth');
	return;
      }

    if ($mesg->code)
      {
	$error_mesg = "ldap search($uri): bind: ".$mesg->error;

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('auth');
	return;
      }

    $mesg = $ldap->search(
			  base   => $base,
			  scope  => $scope,
			  filter => $filter,
			  attrs  => ['description']
			 );

    if ($mesg->code)
      {
	$error_mesg = "ldap search($uri): ".ldap_error_desc($mesg->code);

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('auth');
	return;
      }

    foreach $entry ($mesg->all_entries)
      {
	@Description = $entry->get_value('description');

	undef $subject;
	foreach (@Description)
 	  {
 	    if (/^subject=\s*(.*)/)
 	      {
 		$subject = $1;
		last;
 	      }
 	  }
	$subject || next;

	addAuthUser(\$subject);
      }

    $mesg = $ldap->unbind;

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub authSearch($)
  {
    my ($uri_string) = @_;

    my $uri;
    my $error_mesg;

    writeWarnLog("Loading registered certificate subjects from $uri_string\n");

    $uri = URI->new($uri_string);

    unless ($uri)
      {
	setStatus('auth');
	return;
      }

    if ($uri->scheme =~ /^ldaps?$/)
      {
	authSearch::ldap(\$uri);
      }
    else
      {
	$error_mesg = "auth search($uri): ".
	  $uri->scheme.' connection not supported';

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('auth');
	return;
      }
  }

#-----------------------------------------------------------------------------#

sub memberSearch::ldap($$)
  {
    my $uri     = ${shift()};
    my $lcluser = ${shift()};

    my $scheme;
    my $host;
    my $port;
    my $base;
    my $scope;
    my $filter;
    my $ldap;
    my $mesg;
    my $entry;
    my $subject;
    my $error_mesg;
    my $member;
    my @Description;
    my @Member;
    my %MEMBER;

    $scheme = $uri->scheme;
    $host   = $uri->host;
    $port   = $uri->port;
    $base   = $uri->dn;
    $scope  = $uri->_scope || 'base';
    $filter = $uri->filter;

    if ($scheme eq 'ldap')
      {
	$ldap = Net::LDAP->new($host,
			       port    => $port,
			       timeout => $timeout,
			       onerror => undef
			      );
      }
    elsif ($scheme eq 'ldaps')
      {
	setEnv::ldaps;

	$ldap = Net::LDAPS->new($host,
				port       => $port,
				timeout    => $timeout,
				version    => '3',
				verify     => 'require',
				ciphers    => 'HIGH:MEDIUM',
				clientcert => $ENV{HTTPS_CERT_FILE},
				clientkey  => $ENV{HTTPS_KEY_FILE},
				capath     => $ENV{HTTPS_CA_DIR},
				keydecrypt => \&getPassPhrase,
				onerror    => undef
			       );
      }

    unless ($ldap)
      {
	$error_mesg = "ldap search($uri): Connection failed";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }

    $SIG{ALRM} = sub { die };
    eval
      {
	alarm $timeout;
	$mesg = $ldap->bind;
	alarm 0;
      };

    unless ($mesg)
      {
	$error_mesg = "ldap search($uri): bind: Timeout";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }

    if ($mesg->code)
      {
	$error_mesg = "ldap search($uri): bind: ".$mesg->error;

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }

    $mesg = $ldap->search(
			  base   => $base,
			  scope  => $scope,
			  filter => $filter,
			  attrs  => ['member']
			 );

    if ($mesg->code)
      {
	$error_mesg = "ldap search($uri): ".ldap_error_desc($mesg->code);

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }

    @Member = ();
    while ($group = $mesg->pop_entry())
      {
	push(@Member, $group->get_value('member'));
      }

    %MEMBER = ();
    foreach $member (@Member)
      {
	unless (exists $MEMBER{$member})
	  {
	    $MEMBER{$member} = undef;
	  }
      }

    foreach $member (keys %MEMBER)
      {
	$mesg = $ldap->search(
			      base   => $member,
			      scope  => 'base',
			      filter => '(description=subject=*)',
			      attrs  => ['description']
			     );

	if ($mesg->code)
	  {
	    $error_mesg = "'$member': ".ldap_error_desc($mesg->code);

	    writeWarnLog("$error_mesg\n");
	    next;
	  }

	unless ($entry = $mesg->pop_entry())
	  {
	    writeWarnLog("'$member': Denied by ldap search filter\n");
	    next;
	  }

	@Description = $entry->get_value('description');

	undef $subject;
	foreach (@Description)
	  {
	    if (/^subject=\s*(.*)/)
	      {
		$subject = $1;
		last;
	      }
	  }
	$subject || next;

	addGridUser(\$uri, \$subject, \$lcluser);
      }

    $mesg = $ldap->unbind;

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub memberSearch::http($$)
  {
    my $uri     = ${shift()};
    my $lcluser = ${shift()};

    my $subject;
    my $code;
    my $ref_Subject;
    my @Subject;

    ($code, $ref_Subject) = getSubject::http(\$uri);

    unless ($code)
      {
	setStatus($lcluser);
	return;
      }

    @Subject = @$ref_Subject;

    foreach $subject (@Subject)
      {
	addGridUser(\$uri, \$subject, \$lcluser);
      }

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub memberSearch::voms($$)
  {
    my $uri     = ${shift()};
    my $lcluser = ${shift()};

    my $subject;
    my $code;
    my $ref_Subject;
    my @Subject;

    ($code, $ref_Subject) = getSubject::voms(\$uri);

    unless ($code)
      {
	setStatus($lcluser);
	return;
      }

    @Subject = @$ref_Subject;

    foreach $subject (@Subject)
      {
	addGridUser(\$uri, \$subject, \$lcluser);
      }

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub memberSearch(@)
  {
    my $uri_string = shift;
    my $lcluser    = shift;

    my $uri;
    my $error_mesg;

    writeWarnLog("Loading certificate subjects from $uri_string\n");

    if (($lcluser eq 'AUTO') && !(-e $get_user))
      {
	$error_mesg = "member search($uri_string): ".
	  "[AUTO] local user requires $get_user";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }

    $uri = URI->new($uri_string);

    unless ($uri)
      {
	setStatus($lcluser);
	return;
      }

    if ($uri->scheme =~ /^ldaps?$/)
      {
	memberSearch::ldap(\$uri, \$lcluser);
      }
    elsif ($uri->scheme =~ /^https?$/)
      {
	memberSearch::http(\$uri, \$lcluser);
      }
    elsif ($uri->scheme =~ /^vomss?$/)
      {
        memberSearch::voms(\$uri, \$lcluser);
      }
    else
      {
	$error_mesg = "member search($uri): ".
	  $uri->scheme.' connection not supported';

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus($lcluser);
	return;
      }
  }

#-----------------------------------------------------------------------------#

sub read_gmf_local($)
  {
    my ($gmf_local) = @_;

    my $line;
    my $subject;
    my $lcluser;
    my $error_mesg;

    writeWarnLog("Loading grid-mapfile entries from $gmf_local\n");

    unless (-e $gmf_local)
      {
	$error_mesg = "File $gmf_local not found";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return;
      }

    unless (-r $gmf_local)
      {
	$error_mesg = "File $gmf_local not readable";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return;
      }

    unless (open(IN, "< $gmf_local"))
      {
	$error_mesg = "Unable to open $gmf_local";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	return;
      }

    while ($line = <IN>)
      {
	chomp($line);

	$line || next;

	next if ($line =~ /^\s*\#+/);

 	if ($line !~ /".*".*"/ && $line !~ /\\"/ &&
	    $line =~ /^\s*"(.+)"\s+([^\s,]+)(,([^\s,]+))*\s*$/)
	  {
	    $subject = $1;
	    $lcluser = $2;

	    writeWarnLog("\"$subject\" $lcluser\n");

	    if (! exists $GRID_USER{$subject})
	      {
		$GRID_USER{$subject} = $lcluser;
	      }
	  }
	else
	  {
	    $error_mesg = "$gmf_local: skipping malformed line: '$line'";

	    writeSysLog('info', $error_mesg);
	    writeErrLog("$error_mesg\n\n");
	    setStatus('conf');
	  }
      }

    close(IN);

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub readConf()
  {
    my $line;
    my $key;
    my $den;
    my $all;
    my $group;
    my $acl;
    my $action;
    my $expr;
    my $i;
    my $error_mesg;
    my @Key;
    my @Val;
    my @Expr;

    @Key = ('group',
	    'allow',
	    'deny',
	    'default_lcluser',
	    'gmf_local',
	    'auth');

    $den = 0;
    $all = 0;

    writeWarnLog("Loading configuration from $opt_conf\n");

    unless (-e $opt_conf)
      {
	$error_mesg = "File $opt_conf not found";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('conf');
	exitHandling;
      }

    unless (-r $opt_conf)
      {
	$error_mesg = "File $opt_conf not readable";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('conf');
	exitHandling;
      }

    unless (open(IN, "< $opt_conf"))
      {
	$error_mesg = "Unable to open $opt_conf";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n\n");

	setStatus('conf');
	exitHandling;
      }

    while ($line = <IN>)
      {
	chomp($line);

	$line || next;

	next if ($line =~ /^\s*\#+/);

	@Val = grep $_, split(/\s|\"(.*)\"|\'(.*)\'/, $line);

        $key = lc(shift(@Val));

	unless (grep /$key$/, @Key)
	  {
	    writeWarnLog("Unknown option '$key'\n");
	    next;
	  }

	unless (@Val)
	  {
	    writeWarnLog("Option '$key' requires a value\n");
	    next;
	  }

	if ($key eq 'group')
	  {
	    if ($Val[1])
	      {
		push(@GROUP, [$Val[0], $Val[1]]);
	      }
	    else
	      {
		push(@GROUP, [$Val[0]]);
	      }
	  }
	elsif ($key eq 'allow')
	  {
	    push(@ACL, [$key, $Val[0]]);
	    $all++;
	  }
	elsif ($key eq 'deny')
	  {
	    push(@ACL, [$key, $Val[0]]);
	    $den++;
	  }
	elsif ($key eq 'default_lcluser')
	  {
	    $default_lcluser = $Val[0];
	  }
	elsif ($key eq 'gmf_local')
	  {
	    push(@GMF_LOCAL, $Val[0]);
	  }
	elsif ($key eq 'auth')
	  {
	    push(@AUTH, $Val[0]);
	  }
      }

    close(IN);

    foreach $group (@GROUP)
      {
	unless (@$group[1])
	  {
	    push(@$group, $default_lcluser);
	  }
      }

    if ($all == 0)
      {
	@ACL = (@ACL, ['allow', '*']);
      }
    else
      {
	@ACL = (@ACL, ['deny', '*']);
      }

    foreach $acl (@ACL)
      {
	$action = @$acl[0];
	$expr   = @$acl[1];

	@Expr = split(/(\\\*)/, $expr);
	for $i (0 .. $#Expr)
	  {
	    unless ($Expr[$i] =~ /\\\*/)
	      {
		$Expr[$i] =~ s/([^\\\w])/\\$1/g;
		$Expr[$i] =~ s/\\\*/.\*/g;
	      }
	  }
	$expr = join('', @Expr);

	push(@RULE, [$action, $expr]);
      }

    writeWarnLog("\n");
  }

#-----------------------------------------------------------------------------#

sub printConf()
  {
    (!$opt_quiet && $opt_verbose) || return;

    my $group;
    my $acl;
    my $gmf_local;
    my $auth;

    print STDERR "Operating configuration\n";

    foreach $group (@GROUP)
      {
	print STDERR "GROUP          : @$group\n";
      }
    foreach $acl (@ACL)
      {
	print STDERR "ACL            : @$acl\n";
      }
    print     STDERR "DEFAULT_LCLUSER: $default_lcluser\n";
    foreach $gmf_local (@GMF_LOCAL)
      {
	print STDERR "GMF_LOCAL      : $gmf_local\n";
      }
    foreach $auth (@AUTH)
      {
	print STDERR "AUTH           : $auth\n";
      }
    print     STDERR "\n";
  }

#-----------------------------------------------------------------------------#

sub writeMap()
  {
    my $subject;
    my $gridmap_new;
    my $gridmap_old;
    my $res;
    my $error_mesg;

    $gridmap_new = -e $gridmap ? "$gridmap.0" : $gridmap;
    $gridmap_old = -e $gridmap ? "$gridmap.1" : $gridmap;

    writeWarnLog("Writing output to $gridmap_new\n");

    unless (open(OUT, "> $gridmap_new"))
      {
	$error_mesg = "Unable to write $gridmap_new";

	writeSysLog('info', $error_mesg);
	writeErrLog("$error_mesg\n");

	setStatus('output');
	exitHandling;
      }

    foreach $subject (sort keys %GRID_USER)
      {
	print OUT "\"$subject\" $GRID_USER{$subject}\n";
      }

    close(OUT);

    return if ($gridmap_old eq $gridmap_new);

    if ($opt_cache)
      {
	if (system("cmp -s $gridmap $gridmap_new") == 0)
	  {
	    writeWarnLog("Deleting identical $gridmap_new\n");

	    $res = unlink $gridmap_new;

	    if ($res == 0)
	      {
		$error_mesg = "Unable to delete $gridmap_new";

		writeSysLog('info', $error_mesg);
		writeErrLog("$error_mesg\n");

		setStatus('output');
	      }

	    return;
	  }
      }

    if (-s $gridmap_new)
      {
	if (-e $gridmap_old)
	  {
	    writeWarnLog("Deleting $gridmap_old\n");

	    $res = unlink $gridmap_old;

	    if ($res == 0)
	      {
		$error_mesg = "Unable to delete $gridmap_old";

		writeSysLog('info', $error_mesg);
		writeErrLog("$error_mesg\n");

		setStatus('output');
	      }
	  }

	writeWarnLog("Linking $gridmap to $gridmap_old\n");

	$res = link($gridmap, $gridmap_old);

	if ($res == 0)
	  {
	    $error_mesg = "Unable to link $gridmap to $gridmap_old";

	    writeSysLog('info', $error_mesg);
	    writeErrLog("$error_mesg\n");

	    setStatus('output');
	  }

	writeWarnLog("Moving $gridmap_new to $gridmap\n");

	$res = move($gridmap_new, $gridmap);

	if ($res == 0)
	  {
	    $error_mesg = "Unable to move $gridmap_new to $gridmap";

	    writeSysLog('info', $error_mesg);
	    writeErrLog("$error_mesg\n");

	    setStatus('output');
	    exitHandling;
	  }
      }
    else
      {
	writeWarnLog("Deleting empty $gridmap_new\n");

	$res = unlink $gridmap_new;

	if ($res == 0)
	  {
	    $error_mesg = "Unable to delete $gridmap_new";

	    writeSysLog('info', $error_mesg);
	    writeErrLog("$error_mesg\n");

	    setStatus('output');
	  }
      }
  }

#-----------------------------------------------------------------------------#

sub printMap()
  {
    my $subject;

    writeWarnLog("Writing output to stdout\n");

    foreach $subject (sort keys %GRID_USER)
      {
	print "\"$subject\" $GRID_USER{$subject}\n";
      }
  }

#-----------------------------------------------------------------------------#

sub printHelp()
  {
    print "edg-mkgridmap [--help] [--version]\n";
    print "              [--conf=<config_file>]\n";
    print "              [--output[=<output_file>]]\n";
    print "              [--quiet] [--verbose]\n";
    print "              [--safe] [--nosafe]\n";
    print "              [--cache] [--nocache]\n";
    print "              [--proxy] [--noproxy]\n";
    print "              [--usermode]\n";
  }

#-----------------------------------------------------------------------------#

sub printVersion()
  {
    print "edg-mkgridmap version $version\n";
  }

#=============================================================================#

$version = '4.0.3';

#-----------------------------------------------------------------------------#

$localstatedir = "/var/lib/edg-mkgridmap";

#-----------------------------------------------------------------------------#

unless (-e ($opt_conf = "$localstatedir/etc/edg-mkgridmap.conf"))
  {
    $opt_conf = "/etc/edg-mkgridmap.conf";
  }

#-----------------------------------------------------------------------------#

$get_user = "/usr/libexec/edg-mkgridmap/local-subject2user";

#-----------------------------------------------------------------------------#

$opt_output = '-';

#-----------------------------------------------------------------------------#

$default_lcluser = '.';

#-----------------------------------------------------------------------------#

@GROUP     = ();
@AUTH      = ();
@GMF_LOCAL = ();
@ACL       = ();
@RULE      = ();
%GRID_USER = ();
%AUTH_USER = ();
%STATUS    = ();

#-----------------------------------------------------------------------------#

%ERRORCODE = (conf   =>  16,
              output =>  32,
	      group  =>  64,
	      auth   => 128);

#-----------------------------------------------------------------------------#

$timeout = 30;

#-----------------------------------------------------------------------------#

GetOptions('conf=s'    => \$opt_conf,
	   'help|h'    => \$opt_help,
	   'version|v' => \$opt_version,
	   'output:s'  => \$opt_output,
	   'quiet'     => \$opt_quiet,
	   'safe!'     => \$opt_safe,
	   'verbose'   => \$opt_verbose,
	   'cache!'    => \$opt_cache,
	   'usermode!' => \$opt_usermode,
	   'proxy!'    => \$opt_proxy);

#-----------------------------------------------------------------------------#

if ($opt_help)
  {
    printHelp;
    exitHandling;
  }

#-----------------------------------------------------------------------------#

if ($opt_version)
  {
    printVersion;
    exitHandling;
  }

#-----------------------------------------------------------------------------#

if ($opt_output ne '-')
  {
    $gridmap = ($opt_output ne '') ? $opt_output : $ENV{GRIDMAP}
      || '/etc/grid-security/grid-mapfile';
  }

#-----------------------------------------------------------------------------#

readConf;

printConf;

#-----------------------------------------------------------------------------#

open(GRID_MAP, $gridmap) or writeWarnLog("Cannot open $gridmap: $!\n");

while (<GRID_MAP>)
  {
    push(@{$OLD_GRP{$2}}, $1) if /^"(.+)"\s+(\S+)/;
  }

close GRID_MAP;

#-----------------------------------------------------------------------------#

foreach $gmf_local (@GMF_LOCAL)
  {
    read_gmf_local($gmf_local);
  }

#-----------------------------------------------------------------------------#

foreach $auth (@AUTH)
  {
    authSearch($auth);
  }

#-----------------------------------------------------------------------------#

foreach $group (@GROUP)
  {
    memberSearch(@$group);
  }

#-----------------------------------------------------------------------------#

foreach my $grp (keys %OLD_GRP)
  {
    next unless $FLAG{$grp} && $opt_safe;

    #
    # ensure the old entries are kept in case of problems...
    #

    foreach my $dn (@{$OLD_GRP{$grp}})
      {
	$GRID_USER{$dn} = $grp unless exists $GRID_USER{$dn} &&
	  $GRID_USER{$dn} !~ /^\./ && $grp =~ /^\./;
      }
  }

#-----------------------------------------------------------------------------#

my %tmp;

foreach my $dn (keys %GRID_USER)
  {
    my $grp = $tmp{$dn} = $GRID_USER{$dn};

    #
    # try ensure compatibility with OpenSSL 0.9.6 as well as >= 0.9.7,
    # unless the alternate form already appears explicitly
    #

    if ($dn =~ s|/Email=|/emailAddress=| || $dn =~ s|/emailAddress=|/Email=|)
      {
        $tmp{$dn} = $grp unless exists $GRID_USER{$dn};
      }
  }

%GRID_USER = %tmp;

#-----------------------------------------------------------------------------#

$gridmap ? writeMap : printMap;

#-----------------------------------------------------------------------------#

exitHandling;

#=============================================================================#
