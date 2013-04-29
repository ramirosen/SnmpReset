#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <net/snmp.h>
#include <net/net_namespace.h>
#include <linux/icmp.h>
#include <net/icmp.h>

/* Developed by: Rami Rosen: http://ramirose.wix.com/ramirosen */
/* ramirose@gmail.com */

/* Supports 64 bit machine; currently no support for 32 bit machines. */
#ifdef F18
static const struct snmp_mib snmp4_net_list[] = {
	SNMP_MIB_ITEM("SyncookiesSent", LINUX_MIB_SYNCOOKIESSENT),
	SNMP_MIB_ITEM("SyncookiesRecv", LINUX_MIB_SYNCOOKIESRECV),
	SNMP_MIB_ITEM("SyncookiesFailed", LINUX_MIB_SYNCOOKIESFAILED),
	SNMP_MIB_ITEM("EmbryonicRsts", LINUX_MIB_EMBRYONICRSTS),
	SNMP_MIB_ITEM("PruneCalled", LINUX_MIB_PRUNECALLED),
	SNMP_MIB_ITEM("RcvPruned", LINUX_MIB_RCVPRUNED),
	SNMP_MIB_ITEM("OfoPruned", LINUX_MIB_OFOPRUNED),
	SNMP_MIB_ITEM("OutOfWindowIcmps", LINUX_MIB_OUTOFWINDOWICMPS),
	SNMP_MIB_ITEM("LockDroppedIcmps", LINUX_MIB_LOCKDROPPEDICMPS),
	SNMP_MIB_ITEM("ArpFilter", LINUX_MIB_ARPFILTER),
	SNMP_MIB_ITEM("TW", LINUX_MIB_TIMEWAITED),
	SNMP_MIB_ITEM("TWRecycled", LINUX_MIB_TIMEWAITRECYCLED),
	SNMP_MIB_ITEM("TWKilled", LINUX_MIB_TIMEWAITKILLED),
	SNMP_MIB_ITEM("PAWSPassive", LINUX_MIB_PAWSPASSIVEREJECTED),
	SNMP_MIB_ITEM("PAWSActive", LINUX_MIB_PAWSACTIVEREJECTED),
	SNMP_MIB_ITEM("PAWSEstab", LINUX_MIB_PAWSESTABREJECTED),
	SNMP_MIB_ITEM("DelayedACKs", LINUX_MIB_DELAYEDACKS),
	SNMP_MIB_ITEM("DelayedACKLocked", LINUX_MIB_DELAYEDACKLOCKED),
	SNMP_MIB_ITEM("DelayedACKLost", LINUX_MIB_DELAYEDACKLOST),
	SNMP_MIB_ITEM("ListenOverflows", LINUX_MIB_LISTENOVERFLOWS),
	SNMP_MIB_ITEM("ListenDrops", LINUX_MIB_LISTENDROPS),
	SNMP_MIB_ITEM("TCPPrequeued", LINUX_MIB_TCPPREQUEUED),
	SNMP_MIB_ITEM("TCPDirectCopyFromBacklog", LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG),
	SNMP_MIB_ITEM("TCPDirectCopyFromPrequeue", LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE),
	SNMP_MIB_ITEM("TCPPrequeueDropped", LINUX_MIB_TCPPREQUEUEDROPPED),
	SNMP_MIB_ITEM("TCPHPHits", LINUX_MIB_TCPHPHITS),
	SNMP_MIB_ITEM("TCPHPHitsToUser", LINUX_MIB_TCPHPHITSTOUSER),
	SNMP_MIB_ITEM("TCPPureAcks", LINUX_MIB_TCPPUREACKS),
	SNMP_MIB_ITEM("TCPHPAcks", LINUX_MIB_TCPHPACKS),
	SNMP_MIB_ITEM("TCPRenoRecovery", LINUX_MIB_TCPRENORECOVERY),
	SNMP_MIB_ITEM("TCPSackRecovery", LINUX_MIB_TCPSACKRECOVERY),
	SNMP_MIB_ITEM("TCPSACKReneging", LINUX_MIB_TCPSACKRENEGING),
	SNMP_MIB_ITEM("TCPFACKReorder", LINUX_MIB_TCPFACKREORDER),
	SNMP_MIB_ITEM("TCPSACKReorder", LINUX_MIB_TCPSACKREORDER),
	SNMP_MIB_ITEM("TCPRenoReorder", LINUX_MIB_TCPRENOREORDER),
	SNMP_MIB_ITEM("TCPTSReorder", LINUX_MIB_TCPTSREORDER),
	SNMP_MIB_ITEM("TCPFullUndo", LINUX_MIB_TCPFULLUNDO),
	SNMP_MIB_ITEM("TCPPartialUndo", LINUX_MIB_TCPPARTIALUNDO),
	SNMP_MIB_ITEM("TCPDSACKUndo", LINUX_MIB_TCPDSACKUNDO),
	SNMP_MIB_ITEM("TCPLossUndo", LINUX_MIB_TCPLOSSUNDO),
	SNMP_MIB_ITEM("TCPLostRetransmit", LINUX_MIB_TCPLOSTRETRANSMIT),
	SNMP_MIB_ITEM("TCPRenoFailures", LINUX_MIB_TCPRENOFAILURES),
	SNMP_MIB_ITEM("TCPSackFailures", LINUX_MIB_TCPSACKFAILURES),
	SNMP_MIB_ITEM("TCPLossFailures", LINUX_MIB_TCPLOSSFAILURES),
	SNMP_MIB_ITEM("TCPFastRetrans", LINUX_MIB_TCPFASTRETRANS),
	SNMP_MIB_ITEM("TCPForwardRetrans", LINUX_MIB_TCPFORWARDRETRANS),
	SNMP_MIB_ITEM("TCPSlowStartRetrans", LINUX_MIB_TCPSLOWSTARTRETRANS),
	SNMP_MIB_ITEM("TCPTimeouts", LINUX_MIB_TCPTIMEOUTS),
	SNMP_MIB_ITEM("TCPRenoRecoveryFail", LINUX_MIB_TCPRENORECOVERYFAIL),
	SNMP_MIB_ITEM("TCPSackRecoveryFail", LINUX_MIB_TCPSACKRECOVERYFAIL),
	SNMP_MIB_ITEM("TCPSchedulerFailed", LINUX_MIB_TCPSCHEDULERFAILED),
	SNMP_MIB_ITEM("TCPRcvCollapsed", LINUX_MIB_TCPRCVCOLLAPSED),
	SNMP_MIB_ITEM("TCPDSACKOldSent", LINUX_MIB_TCPDSACKOLDSENT),
	SNMP_MIB_ITEM("TCPDSACKOfoSent", LINUX_MIB_TCPDSACKOFOSENT),
	SNMP_MIB_ITEM("TCPDSACKRecv", LINUX_MIB_TCPDSACKRECV),
	SNMP_MIB_ITEM("TCPDSACKOfoRecv", LINUX_MIB_TCPDSACKOFORECV),
	SNMP_MIB_ITEM("TCPAbortOnData", LINUX_MIB_TCPABORTONDATA),
	SNMP_MIB_ITEM("TCPAbortOnClose", LINUX_MIB_TCPABORTONCLOSE),
	SNMP_MIB_ITEM("TCPAbortOnMemory", LINUX_MIB_TCPABORTONMEMORY),
	SNMP_MIB_ITEM("TCPAbortOnTimeout", LINUX_MIB_TCPABORTONTIMEOUT),
	SNMP_MIB_ITEM("TCPAbortOnLinger", LINUX_MIB_TCPABORTONLINGER),
	SNMP_MIB_ITEM("TCPAbortFailed", LINUX_MIB_TCPABORTFAILED),
	SNMP_MIB_ITEM("TCPMemoryPressures", LINUX_MIB_TCPMEMORYPRESSURES),
	SNMP_MIB_ITEM("TCPSACKDiscard", LINUX_MIB_TCPSACKDISCARD),
	SNMP_MIB_ITEM("TCPDSACKIgnoredOld", LINUX_MIB_TCPDSACKIGNOREDOLD),
	SNMP_MIB_ITEM("TCPDSACKIgnoredNoUndo", LINUX_MIB_TCPDSACKIGNOREDNOUNDO),
	SNMP_MIB_ITEM("TCPSpuriousRTOs", LINUX_MIB_TCPSPURIOUSRTOS),
	SNMP_MIB_ITEM("TCPMD5NotFound", LINUX_MIB_TCPMD5NOTFOUND),
	SNMP_MIB_ITEM("TCPMD5Unexpected", LINUX_MIB_TCPMD5UNEXPECTED),
	SNMP_MIB_ITEM("TCPSackShifted", LINUX_MIB_SACKSHIFTED),
	SNMP_MIB_ITEM("TCPSackMerged", LINUX_MIB_SACKMERGED),
	SNMP_MIB_ITEM("TCPSackShiftFallback", LINUX_MIB_SACKSHIFTFALLBACK),
	SNMP_MIB_ITEM("TCPBacklogDrop", LINUX_MIB_TCPBACKLOGDROP),
	SNMP_MIB_ITEM("TCPMinTTLDrop", LINUX_MIB_TCPMINTTLDROP),
	SNMP_MIB_ITEM("TCPDeferAcceptDrop", LINUX_MIB_TCPDEFERACCEPTDROP),
	SNMP_MIB_ITEM("IPReversePathFilter", LINUX_MIB_IPRPFILTER),
	SNMP_MIB_ITEM("TCPTimeWaitOverflow", LINUX_MIB_TCPTIMEWAITOVERFLOW),
	SNMP_MIB_ITEM("TCPReqQFullDoCookies", LINUX_MIB_TCPREQQFULLDOCOOKIES),
	SNMP_MIB_ITEM("TCPReqQFullDrop", LINUX_MIB_TCPREQQFULLDROP),
	SNMP_MIB_ITEM("TCPRetransFail", LINUX_MIB_TCPRETRANSFAIL),
	SNMP_MIB_ITEM("TCPRcvCoalesce", LINUX_MIB_TCPRCVCOALESCE),
	SNMP_MIB_ITEM("TCPOFOQueue", LINUX_MIB_TCPOFOQUEUE),
	SNMP_MIB_ITEM("TCPOFODrop", LINUX_MIB_TCPOFODROP),
	SNMP_MIB_ITEM("TCPOFOMerge", LINUX_MIB_TCPOFOMERGE),
	SNMP_MIB_ITEM("TCPChallengeACK", LINUX_MIB_TCPCHALLENGEACK),
	SNMP_MIB_ITEM("TCPSYNChallenge", LINUX_MIB_TCPSYNCHALLENGE),
	SNMP_MIB_ITEM("TCPFastOpenActive", LINUX_MIB_TCPFASTOPENACTIVE),
	SNMP_MIB_ITEM("TCPFastOpenPassive", LINUX_MIB_TCPFASTOPENPASSIVE),
	SNMP_MIB_ITEM("TCPFastOpenPassiveFail", LINUX_MIB_TCPFASTOPENPASSIVEFAIL),
	SNMP_MIB_ITEM("TCPFastOpenListenOverflow", LINUX_MIB_TCPFASTOPENLISTENOVERFLOW),
	SNMP_MIB_ITEM("TCPFastOpenCookieReqd", LINUX_MIB_TCPFASTOPENCOOKIEREQD),
	SNMP_MIB_SENTINEL
};
#else
static const struct snmp_mib snmp4_net_list[] = {
         SNMP_MIB_ITEM("SyncookiesSent", LINUX_MIB_SYNCOOKIESSENT),
         SNMP_MIB_ITEM("SyncookiesRecv", LINUX_MIB_SYNCOOKIESRECV),
         SNMP_MIB_ITEM("SyncookiesFailed", LINUX_MIB_SYNCOOKIESFAILED),
         SNMP_MIB_ITEM("EmbryonicRsts", LINUX_MIB_EMBRYONICRSTS),
         SNMP_MIB_ITEM("PruneCalled", LINUX_MIB_PRUNECALLED),
         SNMP_MIB_ITEM("RcvPruned", LINUX_MIB_RCVPRUNED),
         SNMP_MIB_ITEM("OfoPruned", LINUX_MIB_OFOPRUNED),
         SNMP_MIB_ITEM("OutOfWindowIcmps", LINUX_MIB_OUTOFWINDOWICMPS),
         SNMP_MIB_ITEM("LockDroppedIcmps", LINUX_MIB_LOCKDROPPEDICMPS),
         SNMP_MIB_ITEM("ArpFilter", LINUX_MIB_ARPFILTER),
         SNMP_MIB_ITEM("TW", LINUX_MIB_TIMEWAITED),
         SNMP_MIB_ITEM("TWRecycled", LINUX_MIB_TIMEWAITRECYCLED),
         SNMP_MIB_ITEM("TWKilled", LINUX_MIB_TIMEWAITKILLED),
         SNMP_MIB_ITEM("PAWSPassive", LINUX_MIB_PAWSPASSIVEREJECTED),
         SNMP_MIB_ITEM("PAWSActive", LINUX_MIB_PAWSACTIVEREJECTED),
         SNMP_MIB_ITEM("PAWSEstab", LINUX_MIB_PAWSESTABREJECTED),
         SNMP_MIB_ITEM("DelayedACKs", LINUX_MIB_DELAYEDACKS),
         SNMP_MIB_ITEM("DelayedACKLocked", LINUX_MIB_DELAYEDACKLOCKED),
         SNMP_MIB_ITEM("DelayedACKLost", LINUX_MIB_DELAYEDACKLOST),
         SNMP_MIB_ITEM("ListenOverflows", LINUX_MIB_LISTENOVERFLOWS),
         SNMP_MIB_ITEM("ListenDrops", LINUX_MIB_LISTENDROPS),
         SNMP_MIB_ITEM("TCPPrequeued", LINUX_MIB_TCPPREQUEUED),
         SNMP_MIB_ITEM("TCPDirectCopyFromBacklog", LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG),
         SNMP_MIB_ITEM("TCPDirectCopyFromPrequeue", LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE),
         SNMP_MIB_ITEM("TCPPrequeueDropped", LINUX_MIB_TCPPREQUEUEDROPPED),
         SNMP_MIB_ITEM("TCPHPHits", LINUX_MIB_TCPHPHITS),
         SNMP_MIB_ITEM("TCPHPHitsToUser", LINUX_MIB_TCPHPHITSTOUSER),
         SNMP_MIB_ITEM("TCPPureAcks", LINUX_MIB_TCPPUREACKS),
         SNMP_MIB_ITEM("TCPHPAcks", LINUX_MIB_TCPHPACKS),
         SNMP_MIB_ITEM("TCPRenoRecovery", LINUX_MIB_TCPRENORECOVERY),
         SNMP_MIB_ITEM("TCPSackRecovery", LINUX_MIB_TCPSACKRECOVERY),
         SNMP_MIB_ITEM("TCPSACKReneging", LINUX_MIB_TCPSACKRENEGING),
         SNMP_MIB_ITEM("TCPFACKReorder", LINUX_MIB_TCPFACKREORDER),
         SNMP_MIB_ITEM("TCPSACKReorder", LINUX_MIB_TCPSACKREORDER),
         SNMP_MIB_ITEM("TCPRenoReorder", LINUX_MIB_TCPRENOREORDER),
         SNMP_MIB_ITEM("TCPTSReorder", LINUX_MIB_TCPTSREORDER),
         SNMP_MIB_ITEM("TCPFullUndo", LINUX_MIB_TCPFULLUNDO),
         SNMP_MIB_ITEM("TCPPartialUndo", LINUX_MIB_TCPPARTIALUNDO),
         SNMP_MIB_ITEM("TCPDSACKUndo", LINUX_MIB_TCPDSACKUNDO),
         SNMP_MIB_ITEM("TCPLossUndo", LINUX_MIB_TCPLOSSUNDO),
         SNMP_MIB_ITEM("TCPLoss", LINUX_MIB_TCPLOSS),
         SNMP_MIB_ITEM("TCPLostRetransmit", LINUX_MIB_TCPLOSTRETRANSMIT),
         SNMP_MIB_ITEM("TCPRenoFailures", LINUX_MIB_TCPRENOFAILURES),
         SNMP_MIB_ITEM("TCPSackFailures", LINUX_MIB_TCPSACKFAILURES),
         SNMP_MIB_ITEM("TCPLossFailures", LINUX_MIB_TCPLOSSFAILURES),
         SNMP_MIB_ITEM("TCPFastRetrans", LINUX_MIB_TCPFASTRETRANS),
         SNMP_MIB_ITEM("TCPForwardRetrans", LINUX_MIB_TCPFORWARDRETRANS),
         SNMP_MIB_ITEM("TCPSlowStartRetrans", LINUX_MIB_TCPSLOWSTARTRETRANS),
         SNMP_MIB_ITEM("TCPTimeouts", LINUX_MIB_TCPTIMEOUTS),
         SNMP_MIB_ITEM("TCPRenoRecoveryFail", LINUX_MIB_TCPRENORECOVERYFAIL),
         SNMP_MIB_ITEM("TCPSackRecoveryFail", LINUX_MIB_TCPSACKRECOVERYFAIL),
         SNMP_MIB_ITEM("TCPSchedulerFailed", LINUX_MIB_TCPSCHEDULERFAILED),
         SNMP_MIB_ITEM("TCPRcvCollapsed", LINUX_MIB_TCPRCVCOLLAPSED),
         SNMP_MIB_ITEM("TCPDSACKOldSent", LINUX_MIB_TCPDSACKOLDSENT),
         SNMP_MIB_ITEM("TCPDSACKOfoSent", LINUX_MIB_TCPDSACKOFOSENT),
         SNMP_MIB_ITEM("TCPDSACKRecv", LINUX_MIB_TCPDSACKRECV),
         SNMP_MIB_ITEM("TCPDSACKOfoRecv", LINUX_MIB_TCPDSACKOFORECV),
         SNMP_MIB_ITEM("TCPAbortOnSyn", LINUX_MIB_TCPABORTONSYN),
         SNMP_MIB_ITEM("TCPAbortOnData", LINUX_MIB_TCPABORTONDATA),
         SNMP_MIB_ITEM("TCPAbortOnClose", LINUX_MIB_TCPABORTONCLOSE),
         SNMP_MIB_ITEM("TCPAbortOnMemory", LINUX_MIB_TCPABORTONMEMORY),
         SNMP_MIB_ITEM("TCPAbortOnTimeout", LINUX_MIB_TCPABORTONTIMEOUT),
         SNMP_MIB_ITEM("TCPAbortOnLinger", LINUX_MIB_TCPABORTONLINGER),
         SNMP_MIB_ITEM("TCPAbortFailed", LINUX_MIB_TCPABORTFAILED),
         SNMP_MIB_ITEM("TCPMemoryPressures", LINUX_MIB_TCPMEMORYPRESSURES),
         SNMP_MIB_ITEM("TCPSACKDiscard", LINUX_MIB_TCPSACKDISCARD),
         SNMP_MIB_ITEM("TCPDSACKIgnoredOld", LINUX_MIB_TCPDSACKIGNOREDOLD),
         SNMP_MIB_ITEM("TCPDSACKIgnoredNoUndo", LINUX_MIB_TCPDSACKIGNOREDNOUNDO),
         SNMP_MIB_ITEM("TCPSpuriousRTOs", LINUX_MIB_TCPSPURIOUSRTOS),
         SNMP_MIB_ITEM("TCPMD5NotFound", LINUX_MIB_TCPMD5NOTFOUND),
         SNMP_MIB_ITEM("TCPMD5Unexpected", LINUX_MIB_TCPMD5UNEXPECTED),
         SNMP_MIB_ITEM("TCPSackShifted", LINUX_MIB_SACKSHIFTED),
         SNMP_MIB_ITEM("TCPSackMerged", LINUX_MIB_SACKMERGED),
         SNMP_MIB_ITEM("TCPSackShiftFallback", LINUX_MIB_SACKSHIFTFALLBACK),
         SNMP_MIB_SENTINEL
};
#endif
/* Following RFC4293 items are displayed in /proc/net/netstat */
static const struct snmp_mib snmp4_ipextstats_list[] = {
	SNMP_MIB_ITEM("InNoRoutes", IPSTATS_MIB_INNOROUTES),
	SNMP_MIB_ITEM("InTruncatedPkts", IPSTATS_MIB_INTRUNCATEDPKTS),
	SNMP_MIB_ITEM("InMcastPkts", IPSTATS_MIB_INMCASTPKTS),
	SNMP_MIB_ITEM("OutMcastPkts", IPSTATS_MIB_OUTMCASTPKTS),
	SNMP_MIB_ITEM("InBcastPkts", IPSTATS_MIB_INBCASTPKTS),
	SNMP_MIB_ITEM("OutBcastPkts", IPSTATS_MIB_OUTBCASTPKTS),
	SNMP_MIB_ITEM("InOctets", IPSTATS_MIB_INOCTETS),
	SNMP_MIB_ITEM("OutOctets", IPSTATS_MIB_OUTOCTETS),
	SNMP_MIB_ITEM("InMcastOctets", IPSTATS_MIB_INMCASTOCTETS),
	SNMP_MIB_ITEM("OutMcastOctets", IPSTATS_MIB_OUTMCASTOCTETS),
	SNMP_MIB_ITEM("InBcastOctets", IPSTATS_MIB_INBCASTOCTETS),
	SNMP_MIB_ITEM("OutBcastOctets", IPSTATS_MIB_OUTBCASTOCTETS),
	SNMP_MIB_SENTINEL
};

/* snmp items */
static const struct snmp_mib snmp4_ipstats_list[] = {
	SNMP_MIB_ITEM("InReceives", IPSTATS_MIB_INPKTS),
	SNMP_MIB_ITEM("InHdrErrors", IPSTATS_MIB_INHDRERRORS),
	SNMP_MIB_ITEM("InAddrErrors", IPSTATS_MIB_INADDRERRORS),
	SNMP_MIB_ITEM("ForwDatagrams", IPSTATS_MIB_OUTFORWDATAGRAMS),
	SNMP_MIB_ITEM("InUnknownProtos", IPSTATS_MIB_INUNKNOWNPROTOS),
	SNMP_MIB_ITEM("InDiscards", IPSTATS_MIB_INDISCARDS),
	SNMP_MIB_ITEM("InDelivers", IPSTATS_MIB_INDELIVERS),
	SNMP_MIB_ITEM("OutRequests", IPSTATS_MIB_OUTPKTS),
	SNMP_MIB_ITEM("OutDiscards", IPSTATS_MIB_OUTDISCARDS),
	SNMP_MIB_ITEM("OutNoRoutes", IPSTATS_MIB_OUTNOROUTES),
	SNMP_MIB_ITEM("ReasmTimeout", IPSTATS_MIB_REASMTIMEOUT),
	SNMP_MIB_ITEM("ReasmReqds", IPSTATS_MIB_REASMREQDS),
	SNMP_MIB_ITEM("ReasmOKs", IPSTATS_MIB_REASMOKS),
	SNMP_MIB_ITEM("ReasmFails", IPSTATS_MIB_REASMFAILS),
	SNMP_MIB_ITEM("FragOKs", IPSTATS_MIB_FRAGOKS),
	SNMP_MIB_ITEM("FragFails", IPSTATS_MIB_FRAGFAILS),
	SNMP_MIB_ITEM("FragCreates", IPSTATS_MIB_FRAGCREATES),
	SNMP_MIB_SENTINEL
};

static const struct {
	const char *name;
	int index;
} icmpmibmap[] = {
	{ "DestUnreachs", ICMP_DEST_UNREACH },
	{ "TimeExcds", ICMP_TIME_EXCEEDED },
	{ "ParmProbs", ICMP_PARAMETERPROB },
	{ "SrcQuenchs", ICMP_SOURCE_QUENCH },
	{ "Redirects", ICMP_REDIRECT },
	{ "Echos", ICMP_ECHO },
	{ "EchoReps", ICMP_ECHOREPLY },
	{ "Timestamps", ICMP_TIMESTAMP },
	{ "TimestampReps", ICMP_TIMESTAMPREPLY },
	{ "AddrMasks", ICMP_ADDRESS },
	{ "AddrMaskReps", ICMP_ADDRESSREPLY },
	{ NULL, 0 }
};



static const struct snmp_mib snmp4_tcp_list[] = {
	SNMP_MIB_ITEM("RtoAlgorithm", TCP_MIB_RTOALGORITHM),
	SNMP_MIB_ITEM("RtoMin", TCP_MIB_RTOMIN),
	SNMP_MIB_ITEM("RtoMax", TCP_MIB_RTOMAX),
	SNMP_MIB_ITEM("MaxConn", TCP_MIB_MAXCONN),
	SNMP_MIB_ITEM("ActiveOpens", TCP_MIB_ACTIVEOPENS),
	SNMP_MIB_ITEM("PassiveOpens", TCP_MIB_PASSIVEOPENS),
	SNMP_MIB_ITEM("AttemptFails", TCP_MIB_ATTEMPTFAILS),
	SNMP_MIB_ITEM("EstabResets", TCP_MIB_ESTABRESETS),
	SNMP_MIB_ITEM("CurrEstab", TCP_MIB_CURRESTAB),
	SNMP_MIB_ITEM("InSegs", TCP_MIB_INSEGS),
	SNMP_MIB_ITEM("OutSegs", TCP_MIB_OUTSEGS),
	SNMP_MIB_ITEM("RetransSegs", TCP_MIB_RETRANSSEGS),
	SNMP_MIB_ITEM("InErrs", TCP_MIB_INERRS),
	SNMP_MIB_ITEM("OutRsts", TCP_MIB_OUTRSTS),
	SNMP_MIB_SENTINEL
};

static const struct snmp_mib snmp4_udp_list[] = {
	SNMP_MIB_ITEM("InDatagrams", UDP_MIB_INDATAGRAMS),
	SNMP_MIB_ITEM("NoPorts", UDP_MIB_NOPORTS),
	SNMP_MIB_ITEM("InErrors", UDP_MIB_INERRORS),
	SNMP_MIB_ITEM("OutDatagrams", UDP_MIB_OUTDATAGRAMS),
	SNMP_MIB_ITEM("RcvbufErrors", UDP_MIB_RCVBUFERRORS),
	SNMP_MIB_ITEM("SndbufErrors", UDP_MIB_SNDBUFERRORS),
	SNMP_MIB_SENTINEL
};

void snmp_zero_field(void __percpu *mib[], int offt)
{
	int i;
	
	for_each_possible_cpu(i) 
		*(((unsigned long *) per_cpu_ptr(mib[0], i)) + offt) = 0;

}


static int __init init_snmp_reset(void)
{
	int i;
#ifdef F18
xxx
	atomic_long_t *ptr = (&init_net)->mib.icmpmsg_statistics->mibs;
#endif
	printk(KERN_DEBUG "Developed  by Rami Rosen (ramirose@gmail.com): http://ramirose.wix.com/ramirosen\n");

	BUILD_BUG_ON(offsetof(struct ipstats_mib, mibs) != 0);
	for (i = 0; snmp4_ipstats_list[i].name != NULL; i++)
			   snmp_zero_field((void __percpu **)(&init_net)->mib.ip_statistics,
					     snmp4_ipstats_list[i].entry);

	for (i = 0; snmp4_tcp_list[i].name != NULL; i++) 
			snmp_zero_field((void __percpu **)(&init_net)->mib.tcp_statistics,
						   				snmp4_tcp_list[i].entry);

	for (i = 0; snmp4_udp_list[i].name != NULL; i++)
  	  snmp_zero_field((void __percpu **)(&init_net)->mib.udp_statistics,
				   snmp4_udp_list[i].entry);

	for (i = 0; snmp4_net_list[i].name != NULL; i++)
  	snmp_zero_field((void __percpu **)(&init_net)->mib.net_statistics,
					     snmp4_net_list[i].entry);

	for (i = 0; snmp4_ipextstats_list[i].name != NULL; i++)
  	snmp_zero_field((void __percpu **)(&init_net)->mib.ip_statistics,
					     snmp4_ipextstats_list[i].entry);
#ifdef F18 
	for (i=0; icmpmibmap[i].name != NULL; i++) {
    atomic_long_set((ptr + icmpmibmap[i].index), 0);
	  atomic_long_set((ptr + (icmpmibmap[i].index | 0x100)), 0);
	}
#else
	for (i=0; icmpmibmap[i].name != NULL; i++) {
  	snmp_zero_field((void __percpu **)(&init_net)->mib.ip_statistics,
					     icmpmibmap[i].index);
  	snmp_zero_field((void __percpu **)(&init_net)->mib.ip_statistics,
					     (icmpmibmap[i].index | 0x100));
	}
#endif

	snmp_zero_field((void __percpu **)(&init_net)->mib.icmp_statistics, ICMP_MIB_INMSGS);
	snmp_zero_field((void __percpu **)(&init_net)->mib.icmp_statistics, ICMP_MIB_INERRORS);		
	snmp_zero_field((void __percpu **)(&init_net)->mib.icmp_statistics, ICMP_MIB_OUTMSGS);
	snmp_zero_field((void __percpu **)(&init_net)->mib.icmp_statistics, ICMP_MIB_OUTERRORS);		
	

	return 0;
}

static void __exit exit_snmp_reset(void)
{
	printk(KERN_DEBUG "Developed by Rami Rosen (ramirose@gmail.com): http://ramirose.wix.com/ramirosen\n");
}
module_init(init_snmp_reset);
module_exit(exit_snmp_reset);
MODULE_LICENSE("GPL v3");
MODULE_AUTHOR("Rami Rosen <ramirose@gmail.com>");

