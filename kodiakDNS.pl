#
# kodiakDNS.pl - DNS Gathering Tool
#
# Copyright (c) 2012/2015 lain <lain@braincakes.org>
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
use Net::Whois::IP;

print "\n";
print "  kodiakDNS - DNS Gathering Tool\n";
print "\n";
print "       _         _\n";  
print "      ((`'-\"\"\"-'`))\n";
print "       )  -   -  (\n";
print "      /   x _ x   \\     コディアック`DNS\n";
print "      \\   ( + )   /\n";
print "       '-.._^_..-'\n";
print ("\n\n");

# Main

if ($#ARGV < 0 || $#ARGV > 0) { 
    print " Usage: perl $0 <domain> \n\n";
    exit 1;
}

my $domain = @ARGV[0];
my @iplist = ();
my @iprange = ();
my @nsdnamelist = ();
my $hasASN = 0;
my $hasDNSBL = 0;
my @blacklists=("dnsbl.dronebl.org","access.redhawk.org", "bl.csma.biz", "bl.spamcannibal.org", "bl.spamcop.net", "bl.technovision.dk", "blackholes.five-ten-sg.com", "blackholes.wirehub.net", "blacklist.sci.kun.nl", "block.dnsbl.sorbs.net", "blocked.hilli.dk","cart00ney.surriel.com","cbl.abuseat.org","dev.null.dk", "dialup.blacklist.jippg.org", "dialups.mail-abuse.org","dialups.visi.com","dnsbl.ahbl.org","dnsbl.antispam.or.id", "dnsbl.cyberlogic.net","dnsbl.kempt.net", "dnsbl.njabl.org", "dnsbl.sorbs.net", "dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net","dsbl.dnsbl.net.au", "duinv.aupads.org", "dul.dnsbl.sorbs.net","dul.ru", "fl.chickenboner.biz","hil.habeas.com","http.dnsbl.sorbs.net","http.opm.blitzed.org", "intruders.docs.uu.se","korea.services.net", "l1.spews.dnsbl.sorbs.net","l2.spews.dnsbl.sorbs.net","mail-abuse.blacklist.jippg.org","map.spam-rbl.com","misc.dnsbl.sorbs.net", "msgid.bl.gweep.ca", "multihop.dsbl.org", "no-more-funn.moensted.dk","ohps.dnsbl.net.au", "omrs.dnsbl.net.au", "orid.dnsbl.net.au", "orvedb.aupads.org","osps.dnsbl.net.au","osrs.dnsbl.net.au", "owfs.dnsbl.net.au","owps.dnsbl.net.au","probes.dnsbl.net.au","proxy.bl.gweep.ca","psbl.surriel.com","pss.spambusters.org.ar","rbl.schulte.org","rbl.snark.net","rbl.triumf.ca","rdts.dnsbl.net.au","relays.bl.gweep.ca","relays.bl.kundenserver.de","relays.mail-abuse.org","relays.nether.net","ricn.dnsbl.net.au","rmst.dnsbl.net.au","rsbl.aupads.org","sbl.csma.biz", "sbl.spamhaus.org","sbl-xbl.spamhaus.org","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net","socks.opm.blitzed.org","sorbs.dnsbl.net.au","spam.dnsbl.sorbs.net","spam.olsentech.net","spam.wytnij.to","spamguard.leadmon.net","spamsites.dnsbl.net.au","spamsources.dnsbl.info","spamsources.fabel.dk", "spews.dnsbl.net.au", "t1.dnsbl.net.au", "ucepn.dnsbl.net.au", "unconfirmed.dsbl.org", "web.dnsbl.sorbs.net","whois.rfc-ignorant.org","will-spam-for-food.eu.org","wingate.opm.blitzed.org","xbl.spamhaus.org", "zen.spamhaus.org","zombie.dnsbl.sorbs.net" );

print "\n[Domain] $domain \n";

my $res   = Net::DNS::Resolver->new;
my $query = $res->query($domain, "NS");
my $noaxfr = 0;

if ($query) {
    print "\n[Resolving DNS NS]\n\n";

    foreach my $rr (grep { $_->type eq "NS" } $query->answer) {		
	print $rr->string, "\n";
	if ((grep { $_ eq $rr->nsdname } @nsdnamelist)==0) {
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

    foreach my $ip (@iplist) {
       my $position = rindex $ip, '.';
       my $ip_range = substr ($ip,0,$position+1);
       if ((grep { $_ eq $ip_range } @iprange)==0) {
           push(@iprange, $ip_range); 
       }
    }

    print "\n[Resolving Reverse DNS [PTR]]\n";

    foreach my $iprange (@iprange) {
        print "\n".$iprange.'0-255'."\n\n";
	for ($i = 0; $i <= 255; $i++){ 
            resolveReverse($iprange.$i);
	}
    }

    print "\n[Resolving DNS Version]\n\n";
 
    my $dnsversion = `fpdns -D $domain`; 
    print $dnsversion;

    print "\nDo you want to resolve AS Numbers [y/n] (y) ? ";
    $asn =  <STDIN>;
    chomp ($asn);    
    if ((!$asn) || ($asn eq 'y')) {
        print "\n[Resolving AS Number]\n";

        foreach my $iprange (@iprange){
            print "\n".$iprange.'0-255'."\n\n";
            for ($i = 0; $i <= 255; $i++){ 
                resolveASNumber($iprange.$i);
            }
        }
        if ($hasASN == 0) {
            print "\nSearching AS Numbers has no results.\n"
        }
    }

    print "\n\nDo you want to look for IPs in DNS-based block list information/database [y/n] (y) ? ";
    $dnsbl = <STDIN>;
    chomp ($dnsbl);
    if ((!$dnsbl) || ($dnsbl eq 'y')) {
        print "\n[Looking for IPs in DNSBL]\n\n";

        foreach my $iprange (@iprange){
            print "\n".$iprange.'0-255'."\n\n";
            for ($i = 0; $i <= 255; $i++){ 
                if ((grep { $_ eq $iprange.$i } @ipbl)==0){
                    push(@ipbl, $iprange.$i); 
                }
            }
        }

        for my $ip (@ipbl) {       
            $ip=~m/(\d+)\.(\d+)\.(\d+)\.(\d+)/;
            my $arginv=$4.".".$3.".".$2.".".$1;
            $listaips.=" ".$ip;

            for my $bl (@blacklists) {
                my $query = $res->search($arginv.".".$bl);
                if ($query) {
                    my $reason=$res->query($arginv.".".$bl, 'TXT');
                    my $problems.="FOUND $ip in ".$bl."!! (reason: ";

                    for my $txt ($reason->answer) {
                        $problems.=$txt->rdatastr if($txt->type eq "TXT");
                    }
                    $problems.=");; ";
                }
            }
        }
        if ($hasDNSBL == 0) {
            print "\n IPs are not in blacklists.\n"
        }
    }
    print "\n\n";
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
    } 
    elsif ($resolver->errorstring eq "NXDOMAIN" || $resolver->errorstring eq "NOERROR") {
        #warn "$domain NXDOMAIN doesnt exist" . $resolver->errorstring . "\n";
    } 
    else {
     	warn "Cannot resolve host $domain: " . $resolver->errorstring . "\n";
    }
}

sub resolveReverse {
    my $ip = new Net::IP($_[0],4);	 	
    my $mx_res = Net::DNS::Resolver->new();
    my $mxanswer = $mx_res->query($ip->reverse_ip(),'PTR');

    if ($mxanswer) {
        foreach my $mrr (grep {$_->type eq "PTR" } $mxanswer->answer) {
            if ($ip->reverse_ip()) {		
	        print $ip->reverse_ip()," PTR ",$mrr->ptrdname,"\n";
	    } 
            else {
  		print "No Reverse IP \n";
  	    }	 
	}
    } 
    else {
	#print "MX records not found\n";
    }
}

sub resolveASNumber {
    my $ip = $_[0];

    my $response = whoisip_query($ip); 
    foreach (sort keys(%{$response}) ) {
        if (($_ eq "origin") || ($_ eq "OriginAS")) {
            if ($response->{$_}!="") {         
                print "$_ $response->{$_} \n";
                #meterlos en una lista con valores no repetidos
                $hasASN = 1
	    } 
        }
   }
}
