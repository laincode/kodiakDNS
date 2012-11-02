#
# kodiakDNS.pl - DNS Gathering Tool
#
# Copyright (c) 2012/2015 lain <laina@riseup.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     1) Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2) Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#     3) Neither the name of the <organization> nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# Use fpdns (Net-DNS-Fingerprint-0.9.3) http://code.google.com/p/fpdns/
# Use wordlist.txt for bruteforcing
#
#


use Net::DNS;
use Net::IP;

# Main

if ($#ARGV < 0 || $#ARGV > 0) { 
	print "Usage: perl $0 <domain> \n";
	print "    by lain\n\n";
	print "Example: perl $0 google.com\n";	
	exit 1;
}

my $domain = @ARGV[0];
my @iplist = ();
my @iprange = ();
my @nsdnamelist = ();

print "\n[Domain] $domain \n";

my $res   = Net::DNS::Resolver->new;
my $query = $res->query($domain, "NS");
my $noaxfr = 0;

if ($query) {

	print "\n[Resolving DNS NS]\n\n";

	foreach my $rr (grep { $_->type eq "NS" } $query->answer) {		
		print $rr->string, "\n";
		if ((grep { $_ eq $rr->nsdname } @nsdnamelist)==0){
         		push(@nsdnamelist, $rr->nsdname);
		}
	}

	print "\n[Resolving DNS MX]\n\n";

	my @mx = mx($res, $domain);
	foreach my $rrmx (@mx) {	
		print $rrmx->string, "\n";
	}
	

    foreach my $rrns (@nsdnamelist) {
		
    	$res->nameservers($rrns);  	

    	my @zone = $res->axfr($domain);
		if (@zone) {
			$noaxfr = 1;
			print "\n[Resolving AXFR for ".$rrns."]\n\n"; 
  	    	foreach my $rra (@zone) {
      			$rra->print;
				if ($rra->type eq "A") {
					if ((grep { $_ eq $rra->address } @iplist)==0){
         				push(@iplist, $rra->address);
					}
      	   		} 
  	  		}
		}   
	}

	if ($noaxfr == 0){

		print "\n[Resolving DNS A]\n\n";
		foreach my $rrns (@nsdnamelist) {
        	resolveDomain($rrns);
		}  

		print "\n[Resolving DNS by bruteforcing]\n\n"; 
		my $wordlist = "wordlist.txt";

		if ($wordlist) {
			open DATA, $wordlist;
			my @list = ();
			@list = <DATA>;
			close DATA;
        	chomp @list;

			my @mylist = map "$_.$domain", @list;

			foreach my $elto (@mylist){
				resolveDomain($elto);
			}
		}
     }

	print "\n[Resolving Reverse DNS [PTR]]\n";

	foreach my $ip (@iplist){
		my $position = rindex $ip, '.';
		my $ip_range = substr ($ip,0,$position+1);
		if ((grep { $_ eq $ip_range } @iprange)==0){
			push(@iprange, $ip_range); 
		}
	}

	foreach my $iprange (@iprange){
		print "\n".$iprange.'0-255'."\n\n";
		for ($i = 0; $i <= 255; $i++){ 
			resolveReverse($iprange.$i);
		}
	}


	print "\n[Resolving DNS Version]\n\n";

	my $dnsversion = `fpdns -D $domain`; 
	print $dnsversion;

} 
else {
      warn "query failed: ", $res->errorstring, "\n";
}



# Functions

sub resolveDomain {
	my $resolver = Net::DNS::Resolver->new;
    my $domain = $_[0];
	my $query = $resolver->search($domain);
  
	if ($query) {	

		foreach my $rr ($query->answer ? $query->answer : $query->authority) {
			$rr->print;
			if ($rr->type eq "A") {
				if ((grep { $_ eq $rr->address } @iplist)==0){
         			push(@iplist, $rr->address);
				}
      	   	} 
     	}
	} elsif ($resolver->errorstring eq "NXDOMAIN" || $resolver->errorstring eq "NOERROR") {
     		#warn "$domain NXDOMAIN doesnt exist" . $resolver->errorstring . "\n";
	} else {
     		warn "Cannot resolve host $domain: " . $resolver->errorstring . "\n";
	}
}


sub resolveReverse {

	my $ip = new Net::IP($_[0],4);	 	
	my $mx_res = Net::DNS::Resolver->new();
	my $mxanswer = $mx_res->query($ip->reverse_ip(),'PTR');

	if($mxanswer) {
		foreach my $mrr (grep {$_->type eq "PTR" } $mxanswer->answer) {
			if ($ip->reverse_ip()) {		
				print $ip->reverse_ip()," PTR ",$mrr->ptrdname,"\n";
	 		} else {
  				print "No Reverse IP \n";
  			}	 
		}
	} else {
		#print "MX records not found\n";
	}
}


