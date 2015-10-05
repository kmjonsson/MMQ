
package MMQ::Server;

use warnings;
use strict;

use IO::Socket;
use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);
use Encode qw(encode decode);
use Digest::MD5 qw(md5_base64);
use Data::Dumper;
use Log::Log4perl;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

use JSON;

sub random_key {
	my $key = md5_base64(scalar localtime(time) . "MMQ" . rand());
	$key =~ s,[^A-Z0-9a-z],,g;
	return $key;
}

sub new {
	my($class) = shift;
	my($opts)  = shift // {};
	my $self  = {
			'port'     => $opts->{port}  // 4321,
			'addr'     => $opts->{addr}  // '127.0.0.1',
			'key'      => $opts->{key}   // random_key(),
			'debug'    => $opts->{debug} // 0,
			'clients'  => {},
			'idcount'  => 0,
			'sendseq'  => 1,
			'log'   => Log::Log4perl->get_logger(__PACKAGE__),
	};
	bless ($self, $class);
	$self->{server} = IO::Socket::INET->new( Proto     => 'tcp',
										# Addr? => $self->{addr},
										LocalPort => $self->{port},
										Listen    => SOMAXCONN,
										Reuse     => 1);
	return undef unless defined $self->{server};
	$self->{select} = IO::Select->new();
	return undef unless defined $self->{select};
	$self->{select}->add($self->{server});
	return $self;
}

sub key {
	my($self) = @_;
	return $self->{key};
}

sub run {
	my($self) = @_;
	while(1) {
		$self->once();
	}
}

sub once {
	my($self) = @_;
	my(@r) = $self->{select}->can_read(1);
	foreach my $h (@r) {
		if($h == $self->{server}) {
			my $new = $self->{server}->accept;
			$self->{clients}->{$new} = {
				auth    => 0,
				fh      => $new,
				indata  => '',
				id      => $self->{idcount}++,
				queues  => { '*' => 1 },
				rpc     => { },
				error   => 0,
				snoop   => 0,
				rkey    => random_key(),
			};
			$self->{clients}->{$new}->{send} = [ ];
			$self->{select}->add($new);
			$self->sendMsg($self->{clients}->{$new},{
														type 		=> 'AUTH', 
														id 			=> $self->{clients}->{$new}->{id}, 
														challange 	=> $self->{clients}->{$new}->{rkey},
													});
		} else {
			next unless defined $self->{clients}->{$h};
			my $r = $self->process($self->{clients}->{$h});
			if(!defined $r) {
				$self->{select}->remove($h);
				delete $self->{clients}->{$h};
				$h->close();
			}
		}
	}
	my(@w) = $self->{select}->can_write(1/10000);
	foreach my $h (@w) {
		my $client = $self->{clients}->{$h};
		next unless defined $client;
		while(scalar @{$self->{clients}->{$h}->{send}}) {
			my $m = shift @{$self->{clients}->{$h}->{send}};
			if($h->send($m) != length($m)) {
				unshift @{$self->{clients}->{$h}->{send}},$m;
				last;
			}
			chomp($m);
		}
	}
}

sub sendMsg {
	my($self,$client,$msg) = @_;
	print "Send[" . $client->{id}  . "]:". Dumper($msg) if $self->{debug};
	$msg = encode_base64(encode("UTF-8",encode_json($msg)));
	$msg =~ s,[\r\n],,mg;
	foreach my $c (grep { $_->{snoop} == 1 } values %{$self->{clients}}) {
		push @{$c->{send}},"SNOOP To: [" . $client->{id} . "] $msg\r\n";
	}
	push @{$client->{send}},"$msg\r\n";
}

sub process {
	my($self,$client) = @_;
	my $msg;
	$client->{fh}->recv($msg,1024,MSG_DONTWAIT);
	return unless $msg;
	return unless length($msg);
	$client->{indata} .= $msg;
	my(@rows) = split(/[\r\n]+/,$client->{indata});
	if($msg !~ /[\r\n]$/) {
		$client->{indata} = pop @rows;
	} else {
		$client->{indata} = '';
	}
	foreach my $m (@rows) {
		# DEBUG
		if($m =~ /^dump (.*)$/) {
			return unless $1 eq $self->{key};
			push @{$client->{send}},Dumper($client) . "\r\n";
			next;
		}
		if($m =~ /^dumps (.*)$/) {
			return unless $1 eq $self->{key};
			push @{$client->{send}},Dumper($self->{clients}) . "\r\n";
			next;
		}
		if($m =~ /^snoop (.*)$/) {
			return unless $1 eq $self->{key};
			if(!$client->{snoop}) {
				$client->{snoop} = 1;
				push @{$client->{send}},"Snoop ON\r\n";
			} else {
				$client->{snoop} = 0;
				push @{$client->{send}},"Snoop OFF\r\n";
			}
			next;
		}
		# DEBUG
		print "M: $m\n" if $self->{debug};
		my $msg = eval { decode_json(decode("UTF-8",decode_base64($m))) };
		print "Can't decode: $m\n" unless defined $msg;
		print "MSG: " . Dumper($msg) if $self->{debug};
		return if(!defined $msg);
		return if(ref($msg) ne 'HASH');
		return if(!defined $msg->{id});
		return if(!defined $msg->{type});

		if($msg->{type} eq 'AUTH') {
			return if(!defined $msg->{key});
			if($msg->{key} eq hmac_sha1_hex($client->{rkey},$self->{key})) {
				$client->{auth}  = 1;
				$self->sendMsg($client,{
					id => $msg->{id},
					type => 'STATUS',
					status => 'OK',
					client => $client->{id},
				});
			} else {
				return;
			}
			next;
		}
		return if(!$client->{auth});
		# subscribe
		if($msg->{type} eq 'SUBSCRIBE') {
			return if(!defined $msg->{queue});
			$client->{queues}->{$msg->{queue}} = 1;
			$self->sendMsg($client,{
				id => $msg->{id},
				type => 'STATUS',
				status => 'OK',
			});
			next;
		}
		if($msg->{type} eq 'UNSUBSCRIBE') {
			return if(!defined $msg->{queue});
			delete $client->{queues}->{$msg->{queue}};
			$self->sendMsg($client,{
				id => $msg->{id},
				type => 'STATUS',
				status => 'OK',
			});
			next;
		}
		# subscribe rpc
		if($msg->{type} eq 'RPC SUBSCRIBE') {
			return if(!defined $msg->{rpc});
			if(grep { $_->{auth} && defined $_->{rpc}->{$msg->{rpc}}} values %{$self->{clients}}) {
				$self->sendMsg($client,{
					id => $msg->{id},
					type => 'STATUS',
					status => 'ERROR',
				});
			} else {
				$client->{rpc}->{$msg->{rpc}} = 1;
				$self->sendMsg($client,{
					id => $msg->{id},
					type => 'STATUS',
					status => 'OK',
				});
			}
			next;
		}
		if($msg->{type} eq 'RPC UNSUBSCRIBE') {
			return if(!defined $msg->{rpc});
			delete $client->{rpc}->{$msg->{rpc}};
			$self->sendMsg($client,{
				id => $msg->{id},
				type => 'STATUS',
				status => 'OK',
			});
			next;
		}
		# new packet
		if($msg->{type} eq 'PACKET') {
			return if(!defined $msg->{queue});
			return if(!defined $msg->{data});
			$msg->{client} = $client->{id};
			print Dumper($self->{clients}) if $self->{debug};
			foreach my $c (grep { $_ ne $client && $_->{auth} && 
							defined $_->{queues}->{$msg->{queue}}} values %{$self->{clients}}) {
				print Dumper($c) if $self->{debug};
				$self->sendMsg($c,$msg);
			}
			#print "YES! OK: $msg->{id} for $msg->{queue}\n" if $msg->{queue} =~ /MySensors::Controller/;
			$self->sendMsg($client,{
				id => $msg->{id},
				type => 'STATUS',
				status => 'OK',
			});
			next;
		}
		if($msg->{type} eq 'RPC') {
			return if(!defined $msg->{rpc});
			$msg->{client} = $client->{id};
			my $sent = 0;
			print "RPC:" . Dumper($msg) if $self->{debug};
			foreach my $c (grep { $_ ne $client && $_->{auth} && 
							defined $_->{rpc}->{$msg->{rpc}}} values %{$self->{clients}}) {
				$self->sendMsg($c,$msg);
				$sent++;
			}
			if(!$sent) {
				$self->sendMsg($client,{
					id => $msg->{id},
					type => 'STATUS',
					status => 'ERROR',
				});
			}
			next;
		}
		if($msg->{type} eq 'RPR') {
			return if(!defined $msg->{client});
			return if(!defined $msg->{client_id});
			foreach my $c (values %{$self->{clients}}) {
				printf "Checking client: %d\n",$c->{id} if $self->{debug};
				next unless $c->{auth};
				next if $c eq $client;
				next if $c->{id} ne $msg->{client};
				$self->sendMsg($c,{
					id => $msg->{client_id},
					type => 'STATUS',
					status => 'OK',
					data => $msg->{data},
				});
				last;
			}
			$self->sendMsg($client,{
				id => $msg->{id},
				type => 'STATUS',
				status => 'OK',
			});
			next;
		}
		return;
	}
	return 1;
}

1;
