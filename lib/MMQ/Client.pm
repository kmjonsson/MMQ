
package MMQ::Client;

use warnings;
use strict;

use IO::Socket;
use IO::Select;
#use Data::Dumper;
use MIME::Base64 qw(encode_base64 decode_base64);
use Encode qw(encode decode);
use JSON;
use Data::Dumper;
use Log::Log4perl;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex);

sub new {
	my($class) = shift;
	my($opts)  = shift // {};
	my $self  = {
			'port'     => $opts->{port} // 4321,
			'addr'     => $opts->{addr} // '127.0.0.1',
			'key'      => $opts->{key} // '',
			'timeout'  => $opts->{timeout} // 5,
			'callback' => $opts->{callback} // sub { },
			debug      => $opts->{debug} // 0,
			'sendseq'  => 1,
			auth    => 0,
			indata  => '',
			send    => [],
			error   => 0,
			client  => undef,
			select  => IO::Select->new(),
			id		=> undef,
			status  => {},
			queues  => {},
			'log'   => Log::Log4perl->get_logger(__PACKAGE__),
	};
	bless ($self, $class);
	return $self->connect() unless defined $opts->{noconnect};
	return $self;
}

sub getSocket {
	my($self) = @_;
	return $self->{client};
}

sub id {
	my($self) = @_;
	return $self->{id};
}

sub auth {
	my($self) = @_;
	return $self->{auth};
}

sub send {
	my($self,$data,$queue) = @_;
	$queue //= '*';
	my $id = $self->sendMsg({
		'type' => 'PACKET',
		'queue' => $queue,
		'data' => $data,
	});
	my $r = $self->waitId($id);
	$self->{log}->error("Timeout: PACKET ($queue) Data:" . Dumper($data)) unless defined $r;
	return $r;
}

sub rpc {
	my($self,$rpc,$data) = @_;
	my $id = $self->sendMsg({
		'type' => 'RPC',
		'rpc' => $rpc,
		'data' => $data,
	});
	my $msg = $self->waitId($id);
	if(defined $msg) {
		return $msg->{data};
	}
	return;
}

sub waitId {
	my($self,$id) = @_;
	print "Wait for $id\n" if $self->{debug};
	my($package, $filename, $line) = caller;
	if(!defined $self->{client}) {
		 die "waitId: $package, $filename, $line ...";
	}
	my $t = $self->{timeout} + time;
	while($t > time) { 
		$self->once(1);
		if(defined $self->{status}->{$id}) {
			my $msg = $self->{status}->{$id};
			delete $self->{status}->{$id};
			return $msg;
		}
	}
	$self->{log}->error("Timeout :-( msg: $id from ($package, $filename, $line)");
	print "timeout :-(\n" if $self->{debug};
	return;
}

sub rpc_subscribe {
	my($self,$rpc,$callback,$rpcSelf) = @_;
	my $id = $self->sendMsg({
		'type' => 'RPC SUBSCRIBE',
		'rpc' => $rpc,
	});
	my $msg = $self->waitId($id);
	if(defined $msg && $msg->{status} eq 'OK') {
		$self->{rpc}->{$rpc} = { rpc => $callback, self => $rpcSelf // $self };
	}
}

sub rpc_unsubscribe {
	my($self,$rpc) = @_;
	my $id = $self->sendMsg({
		'type' => 'RPC UNSUBSCRIBE',
		'rpc' => $rpc,
	});
	return $self->waitId($id);
}

sub subscribe {
	my($self,$queue,$callback,$callbackSelf) = @_;
	if(!defined $self->{client}) {
		 my($package, $filename, $line) = caller;
		 die "sub: $package, $filename, $line ...";
	}
	my $id = $self->sendMsg({
		'type' => 'SUBSCRIBE',
		'queue' => $queue,
	});
	my $wid = $self->waitId($id);
	if(defined $wid) {
		$self->{queues}->{$queue} = { callback => $callback, self => $callbackSelf // $self };
	}
	return $wid;
}

sub unsubscribe {
	my($self,$queue) = @_;
	my $id = $self->sendMsg({
		'type' => 'UNSUBSCRIBE',
		'queue' => $queue,
	});
	delete $self->{queues}->{$queue};
	return $self->waitId($id);
}

sub sendMsg {
	my($self,$msg) = @_;
	my $id = $msg->{id} = $msg->{id} // $self->{sendseq}++;
	print 'Sending:' . Dumper($msg) if $self->{debug};
	$msg = encode_base64(encode("UTF-8",encode_json($msg)));
	$msg =~ s,[\r\n]+,,mg;
	push @{$self->{send}},"$msg\r\n";
	print "Sending: $msg\n" if $self->{debug};
	return $id;
}

sub run {
	my($self) = @_;
	while(!$self->once()) {
		# do nothing :-)
	}
}

sub close {
	my($self) = @_;
	$self->{client}->close();
	$self->{select}->remove($self->{client});
	$self->{client} = undef;
	return $self;
}

sub connect {
	my($self) = @_;
	$self->{client} = IO::Socket::INET->new( Proto     => 'tcp',
										PeerHost => $self->{addr},
										PeerPort => $self->{port});
	return undef unless defined $self->{client};
	$self->{select}->add($self->{client});

	my $timeout = time + $self->{timeout};
	while($timeout > time) {
		$self->once();
		last if defined $self->{authId};
	}
	if($timeout > time) {
		my $msg = $self->waitId($self->{authId});
		return unless(defined $msg);
		$self->{id} = $msg->{client};
		$self->{auth} = 1;
		return $self;
	}
	return;
}

sub sending {
	my($self) = @_;
	my(@w) = $self->{select}->can_write(1/10000);
	if(scalar @w) {
		while(scalar @{$self->{send}}) {
			my $m = shift @{$self->{send}};
			if($self->{client}->send($m) != length($m)) {
				unshift @{$self->{send}},$m;
				last;
			}
			chomp($m);
			print "S: $m\n" if $self->{debug};
		}
	}
	return $self;
}

sub once {
	my($self,$timeout) = @_;
	$timeout //= 1;
	$self->sending();
	if(!defined $self->{client}) {
		 my($package, $filename, $line) = caller;
		 die "DIE: $package, $filename, $line ...";
	}
	if(!$self->{client}->connected()) {
		$self->close();
		$self->{error}++;
		return $self->{error};
	}
	my(@r) = $self->{select}->can_read($timeout);
	if(scalar @r) {
		my $r = $self->process();
		if(!defined $r) {
			$self->close();
			$self->{error}++;
			return $self->{error};
		}
	}
	$self->sending();
	foreach my $k (keys %{$self->{status}}) {
		delete $self->{status}->{$k} if $self->{status}->{$k}->{_timestamp_}+$self->{timeout}*2 < time;
	}
	return $self->{error};
}

sub process {
	my($self) = @_;
	my $msg;
	$self->{client}->recv($msg,1024,MSG_DONTWAIT);
	printf "Got: $msg (%d) {$$}\n",length($msg) if $self->{debug};
	return unless $msg;
	return unless length($msg);
	$self->{indata} .= $msg;
	my(@rows) = split(/[\r\n]+/,$self->{indata});
	if($msg !~ /[\r\n]$/) {
		$self->{indata} = pop @rows;
	} else {
		$self->{indata} = '';
	}
	foreach my $m (@rows) {
		print "R: $m\n" if $self->{debug};
		my($msg) = decode_json(decode("UTF-8",decode_base64($m)));
		return if(!defined $msg);
		return if(ref($msg) ne 'HASH');
		return if(!defined $msg->{id});
		return if(!defined $msg->{type});

		print Dumper($msg) if $self->{debug};
		print Dumper($msg) if $self->{x_debug};

		if($msg->{type} eq 'AUTH') {
			return unless defined $msg->{challange};
			my $id = $self->sendMsg({
					type => 'AUTH',
					key => hmac_sha1_hex($msg->{challange},$self->{key}),
			});
			$self->{authId} = $id;
			next;
		}

		# status..
		if($msg->{type} eq 'STATUS') {
			return unless defined $msg->{status};
			return unless $msg->{status} eq 'OK';
			$msg->{_timestamp_} = time;
			$self->{status}->{$msg->{id}} = $msg;
			next;
		}

		# need auth
		if(!$self->{auth}) {
			next;
		}

		# RPC
		if($msg->{type} eq 'RPC') {
			return unless defined $msg->{rpc};
			return unless defined $msg->{client};
			if(defined $self->{rpc}->{$msg->{rpc}}) {
				my $rpc = $self->{rpc}->{$msg->{rpc}};
				my $result = eval { &{$rpc->{rpc}}($rpc->{self},$msg->{data}) };
				if(!defined $result && length $@) {
					$self->{log}->error(sprintf("Callback error (rpc):  %d %s %s - %s",$self->{id},$msg->{rpc},$msg->{data},$@));
				}
				$self->sendMsg({
					type => 'RPR',
					client => $msg->{client},
					client_id => $msg->{id},
					data => $result,
				});
			}
			next;
		}

		# packet
		if($msg->{type} eq 'PACKET') {
			return unless defined $msg->{queue};
			return unless defined $msg->{data};
			my $callback = $self->{queues}->{$msg->{queue}};
			printf("G: %d %s %s ($callback)\n",$self->{id},$msg->{queue},$msg->{data}) if $self->{debug};
			next unless defined $callback;
			my $result = eval { &{$callback->{callback}}($callback->{self},$msg->{data},$msg->{queue}) };
			if(!defined $result && length $@) {
				$self->{log}->error(sprintf("Callback error:  %d %s %s - %s",$self->{id},$msg->{queue},$msg->{data},$@));
			}
			next;
		}

		die "End: $m\n" . Dumper($msg);
	}
	return 1;
}

1;
