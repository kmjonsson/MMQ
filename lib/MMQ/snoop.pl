
package MMQ::Client;

use warnings;
use strict;

use IO::Socket;
use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);
use Encode qw(encode decode);
use JSON;
use Data::Dumper;

my $key = shift @ARGV // 'password';

my %filter;
foreach my $f (@ARGV) {
	$filter{$1} = $2 if $f =~ /^([^=]+)=(.*)$/;
}

my $client = IO::Socket::INET->new( Proto     => 'tcp',
									PeerHost => 'localhost',
									PeerPort => 4344,
									) || die;

print $client "snoop $key\r\n";
while(<$client>) {
	s,[\r\n]+,,mg;
	#print "$_\n";
	if(/SNOOP To: \[(\d+)\] (.*)$/) {
		my($msg) = decode_json(decode("UTF-8",decode_base64($2)));
		print "To[$1]: ".Dumper($msg) if show($msg,$1);
	}
}

sub show {
	my($msg,$to) = @_;
	foreach my $key (keys %filter) {
		my $re = $filter{$key};
		if($key eq '_to') {
			return 0 unless $to =~ /$re/;
			next;
		}
		return 0 unless defined $msg->{$key};
		return 0 unless $msg->{$key} =~ /$re/;
	}
	return 1;
}
