/*
* Dibbler - a portable DHCPv6
*
* authors: Tomasz Mrugalski <thomson@klub.com.pl>
*          Marek Senderski <msend@o2.pl>
* changes: Michal Kowalczuk <michal@kowalczuk.eu>
*
* released under GNU GPL v2 only licence
*                                                                           
*/

#include <cmath>
#include "SmartPtr.h"
#include "SrvMsgReply.h"
#include "SrvMsg.h"
#include "SrvOptOptionRequest.h"
#include "SrvOptStatusCode.h"
#include "SrvOptIAAddress.h"
#include "SrvOptIA_NA.h"
#include "SrvOptIA_PD.h"
#include "SrvOptTA.h"
#include "SrvOptRapidCommit.h"
#include "SrvOptServerIdentifier.h"
#include "SrvOptTimeZone.h"
#include "SrvOptDomainName.h"
#include "SrvOptDNSServers.h"
#include "SrvOptNTPServers.h"
#include "SrvOptFQDN.h"
#include "AddrClient.h"
#include "AddrIA.h"
#include "AddrAddr.h"
#include "Logger.h"
#include "fstream"
#include "string.h"
#include "iostream"
#include "algorithm"
#include "SrvMsgAdvertise.h"
#include "vector"
using namespace std;
std::string ipv6_type_rly, ipv6_addr_rly;
std::string ipv6_addr2_rly;
std::string Dec2BinR(int n)
{
	std::string tmp;
	for (int a = n; a; a = a / 2)
	{
		tmp = tmp + (a % 2 ? '1' : '0');
	}
	// 如何利用 reverse方法！！！！！！(已解决)加入algorithm 头文件 调用stl
	reverse(tmp.begin(), tmp.end());
	return tmp;
}

//函数作用：将二进制字符串转十进制
int Bin2DecR(std::string src)
{
	int tmp=0;
	int n = src.size();
	int k = 1;
	int i = 0;
	for (i = n - 1; i >= 0; i--)
	{
		tmp = tmp + (src[i] - '0')*k;
		k = k * 2;
	}


	return tmp;
}
//函数作用：将十进制转十六进制字符串
std:: string Dec2HexR(int n)
{
	std::string tmp;
	char str[20];
	sprintf(str, "%x", n);
	tmp = str;
	return tmp;
}
#ifndef MOD_SRV_DISABLE_DNSUPDATE
#include "DNSUpdate.h"
#endif

/** 
* this constructor is used to create REPLY message as a response for CONFIRM message
* 
* @param ifaceMgr 
* @param transMgr 
* @param CfgMgr 
* @param AddrMgr 
* @param confirm 
*/
TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
						   SmartPtr<TSrvTransMgr> transMgr, 
						   SmartPtr<TSrvCfgMgr> CfgMgr, 
						   SmartPtr<TSrvAddrMgr> AddrMgr,
						   SmartPtr<TSrvMsgConfirm> confirm)
						   :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
						   confirm->getIface(),confirm->getAddr(), REPLY_MSG, 
						   confirm->getTransID())
{
	this->copyRelayInfo((Ptr*)confirm);
	this->copyAAASPI((Ptr*)confirm);
	this->copyRemoteID((Ptr*)confirm);

	SmartPtr<TSrvCfgIface> ptrIface = CfgMgr->getIfaceByID( confirm->getIface() );
	if (!ptrIface) {
		Log(Crit) << "Msg received through not configured interface. "
			"Somebody call an exorcist!" << LogEnd;
		this->IsDone = true;
		return;
	}

	setOptionsReqOptClntDUID((Ptr*)confirm);
	if (!duidOpt) {
		Log(Warning) << "CONFIRM message without client-id option received, message dropped." << LogEnd;
		IsDone = true;
		return;
	}

	// copy client's ID
	SmartPtr<TOpt> ptrOpt;
	ptrOpt = confirm->getOption(OPTION_CLIENTID);
	Options.append(ptrOpt);

	confirm->firstOption();
	bool OnLink = true;
	int checkCnt = 0;
	List(TSrvOptIA_NA) validIAs;

	while ( (ptrOpt = confirm->getOption()) && OnLink ) {

		switch (ptrOpt->getOptType()) {
	case OPTION_IA_NA: {

		SmartPtr<TSrvOptIA_NA> ia = (Ptr*) ptrOpt;
		SmartPtr<TOpt> subOpt;
		unsigned long addrCnt = 0;
		ia->firstOption();
		while ( (subOpt = ia->getOption()) && (OnLink) ) {
			if (subOpt->getOptType() != OPTION_IAADDR){
				continue;
			}

			SmartPtr<TSrvOptIAAddress> optAddr = (Ptr*) subOpt;
			Log(Debug) << "CONFIRM message: checking if " << optAddr->getAddr()->getPlain() << " is supported:";
			if (!CfgMgr->isIAAddrSupported(this->Iface, optAddr->getAddr())) {
				Log(Cont) << "no." << LogEnd;
				OnLink = false;
			} else {
				// FIXME check if it is bound or not. If it is, then check if it is bound to this client
				Log(Cont) << "yes." << LogEnd;
				addrCnt++;
			}
			checkCnt++;
		}
		if(addrCnt){
			SmartPtr<TSrvOptIA_NA> tempIA = new TSrvOptIA_NA(CfgMgr,AddrMgr,ia,
				confirm->getAddr(),duidOpt->getDUID(),confirm->getIface(),
				addrCnt,CONFIRM_MSG,this);
			validIAs.append(tempIA);
		}
		break;
					   }
	case OPTION_IA_TA: {
		SmartPtr<TSrvOptTA> ta = (Ptr*) ptrOpt;
		SmartPtr<TOpt> subOpt;
		ta->firstOption();
		while (subOpt = ta->getOption() && (OnLink)) {
			if (subOpt->getOptType() != OPTION_IAADDR)
				continue;
			SmartPtr<TSrvOptIAAddress> optAddr = (Ptr*) subOpt;
			if (!CfgMgr->isTAAddrSupported(this->Iface, optAddr->getAddr())) {
				OnLink = false;
			}
			checkCnt++;
		}
		break;
					   }
	default:
		// other options - ignore them
		continue;
		}
	}
	if (!checkCnt) {
		// no check
		SmartPtr <TSrvOptStatusCode> ptrCode = 
			new TSrvOptStatusCode(STATUSCODE_NOTONLINK,
			"No addresses checked. Did you send any?",
			this);
		this->Options.append( (Ptr*) ptrCode );
	} else
		if (!OnLink) {
			// not-on-link
			SmartPtr <TSrvOptStatusCode> ptrCode = 
				new TSrvOptStatusCode(STATUSCODE_NOTONLINK,
				"Sorry, those addresses are not valid for this link.",
				this);
			this->Options.append( (Ptr*) ptrCode );
		} else {
			// success
			SmartPtr <TSrvOptStatusCode> ptrCode = 
				new TSrvOptStatusCode(STATUSCODE_SUCCESS,
				"Your addresses are valid! Yahoo!",
				this);
			this->Options.append( (Ptr*) ptrCode);

			int iaNum=validIAs.count();
			if(iaNum){
				SmartPtr<TSrvOptIA_NA> ia;
				validIAs.first();
				while(ia=validIAs.get() ){
					this->Options.append((Ptr*)ia );
				}
			}
		}

		// include our ServerID
		SmartPtr<TSrvOptServerIdentifier> srvDUID=new TSrvOptServerIdentifier(CfgMgr->getDUID(),this);
		this->Options.append((Ptr*)srvDUID);

		appendRequestedOptions(duidOpt->getDUID(), confirm->getAddr(), confirm->getIface(), reqOpts);

		appendStatusCode();

		appendAuthenticationOption(duidOpt->getDUID());

		pkt = new char[this->getSize()];
		IsDone = false;
		this->MRT = 31;
		this->send();
}

/** 
* this constructor is used to create REPLY message as a response for DECLINE message
* 
* @param ifaceMgr 
* @param transMgr 
* @param CfgMgr 
* @param AddrMgr 
* @param decline 
*/TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
							 SmartPtr<TSrvTransMgr> transMgr, 
							 SmartPtr<TSrvCfgMgr> CfgMgr, 
							 SmartPtr<TSrvAddrMgr> AddrMgr,
							 SmartPtr<TSrvMsgDecline> decline)
							 :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
							 decline->getIface(),decline->getAddr(), REPLY_MSG, decline->getTransID())
{
	this->copyRelayInfo((Ptr*)decline);
	this->copyAAASPI((Ptr*)decline);
	this->copyRemoteID((Ptr*)decline);


	SmartPtr<TOpt> ptrOpt;

	// FIXME: Implement DECLINE support for client-id and option request as in other messages
	// include our DUID
	ptrOpt = decline->getOption(OPTION_SERVERID);
	Options.append(ptrOpt);

	// copy client's DUID
	SmartPtr<TSrvOptClientIdentifier> ptrClntDUID;
	ptrOpt = decline->getOption(OPTION_CLIENTID);
	if (!ptrOpt) {
		Log(Warning) << "Received DECLINE message without client-id option. Message ignored." << LogEnd;
		IsDone = true;
		return;
	}
	ptrClntDUID = (Ptr*) ptrOpt;
	Options.append(ptrOpt);
	duidOpt=(Ptr*)ptrOpt;
	SmartPtr<TAddrClient> ptrClient = AddrMgr->getClient(duidOpt->getDUID());
	if (!ptrClient) {
		Log(Warning) << "Received DECLINE from unknown client, DUID=" << *duidOpt->getDUID() << ". Ignored." << LogEnd;
		IsDone = true;
		return;
	}

	SmartPtr<TDUID> declinedDUID = new TDUID("X",1);
	SmartPtr<TAddrClient> declinedClient = AddrMgr->getClient( declinedDUID );
	if (!declinedClient) {
		declinedClient = new TAddrClient( declinedDUID );
		AddrMgr->addClient(declinedClient);
	}

	decline->firstOption();
	while (ptrOpt = decline->getOption() ) 
	{
		switch (ptrOpt->getOptType()) 
		{
			//---------reply中的IA_NA处理方法-------------------------       
		case OPTION_IA_NA: 
			{
				SmartPtr<TSrvOptIA_NA> ptrIA_NA = (Ptr*) ptrOpt;
				SmartPtr<TAddrIA> ptrIA = ptrClient->getIA(ptrIA_NA->getIAID());
				if (!ptrIA) 
				{
					Options.append( new TSrvOptIA_NA(ptrIA_NA->getIAID(), 0, 0, STATUSCODE_NOBINDING,
						"No such IA is bound.",this) );
					continue;
				}

				// create empty IA
				SmartPtr<TSrvOptIA_NA> replyIA_NA = new TSrvOptIA_NA(ptrIA_NA->getIAID(), 0, 0, this);
				int AddrsDeclinedCnt = 0;

				// IA found in DB, now move each addr in DB to "declined-client" and 
				// ignore those, which are not present id DB
				SmartPtr<TOpt> subOpt;
				SmartPtr<TSrvOptIAAddress> addr;
				SmartPtr<TAddrIA> declinedIA = declinedClient->getIA(0);
				if (!declinedIA)
				{
					declinedIA=new TAddrIA(decline->getIface(), SmartPtr<TIPv6Addr>(new TIPv6Addr()), declinedDUID, 0, 0, 0);
					declinedClient->addIA(declinedIA);
				}
				ptrOpt->firstOption();
				while( subOpt = ptrOpt->getOption() ) {
					if (subOpt->getOptType()==OPTION_IAADDR)
					{
						addr = (Ptr*) subOpt;
						addr->setValid(0);
						addr->setPref(0);

						// if there's no such address in out DB
						if (!ptrIA->getAddr( addr->getAddr() ) )
							continue;
						// add this addr to declined addrs...
						declinedIA->addAddr( new TAddrAddr( addr->getAddr(),DECLINED_TIMEOUT,DECLINED_TIMEOUT) );
						// ... and remove it from client's IA...
						ptrIA->delAddr( addr->getAddr() );
						// ... and finally append it in reply
						replyIA_NA->addOption( subOpt );
						AddrsDeclinedCnt++;
					};
				}
				Options.append((Ptr*)replyIA_NA);
				char buf[10];
				sprintf(buf,"%d",AddrsDeclinedCnt);
				string tmp = buf;
				SmartPtr<TSrvOptStatusCode> optStatusCode = 
					new TSrvOptStatusCode(STATUSCODE_SUCCESS,tmp+" addrs declined.",this);
				replyIA_NA->addOption( (Ptr*) optStatusCode );
			};
		case OPTION_IA_TA:
			Log(Info) << "TA address declined. Oh well. Since it's temporary, let's ignore it entirely." << LogEnd;
			break;
		default:
			break;
		}
	}

	appendAuthenticationOption(duidOpt->getDUID());

	pkt = new char[this->getSize()];
	IsDone = false;
	this->MRT = 31;
	this->send();
}

/** 
* this constructor is used to create REPLY message as a response for REBIND message
* 
* @param ifaceMgr 
* @param transMgr 
* @param CfgMgr 
* @param AddrMgr 
* @param rebind 
*/TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
							 SmartPtr<TSrvTransMgr> transMgr, 
							 SmartPtr<TSrvCfgMgr> CfgMgr, 
							 SmartPtr<TSrvAddrMgr> AddrMgr,
							 SmartPtr<TSrvMsgRebind> rebind)
							 :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
							 rebind->getIface(),rebind->getAddr(), REPLY_MSG, rebind->getTransID())
{
	this->copyRelayInfo((Ptr*)rebind);
	this->copyAAASPI((Ptr*)rebind);
	this->copyRemoteID((Ptr*)rebind);

	unsigned long addrCount=0;
	SmartPtr<TOpt> ptrOpt;

	setOptionsReqOptClntDUID((Ptr*)rebind);
	if (!duidOpt) {
		Log(Warning) << "REBIND message without client-id option received, message dropped." << LogEnd;
		IsDone = true;
		return;
	}

	rebind->firstOption();
	while (ptrOpt = rebind->getOption() ) 
	{
		switch (ptrOpt->getOptType()) 
		{
		case OPTION_IA_NA: 
			{
				SmartPtr<TSrvOptIA_NA> optIA_NA;
				optIA_NA = new TSrvOptIA_NA(CfgMgr, AddrMgr, (Ptr*)ptrOpt, 
					rebind->getAddr(), duidOpt->getDUID(),
					rebind->getIface(), addrCount, REBIND_MSG,
					this);
				if (optIA_NA->getStatusCode() != STATUSCODE_NOBINDING )
					this->Options.append((Ptr*)optIA_NA);
				else {
					this->IsDone = true;
					Log(Notice) << "REBIND received with unknown addresses and " 
						<< "was silently discarded." << LogEnd;
					return;
				}
				break;
			}
		case OPTION_IA_PD: {
			SmartPtr<TSrvOptIA_PD> pd;
			pd = new TSrvOptIA_PD(CfgMgr, AddrMgr, (Ptr*) ptrOpt, rebind->getAddr(), 
				duidOpt->getDUID(), rebind->getIface(), REQUEST_MSG, this);
			this->Options.append((Ptr*)pd);
			break;
						   }

		case OPTION_IAADDR:
		case OPTION_RAPID_COMMIT:
		case OPTION_STATUS_CODE:
		case OPTION_PREFERENCE:
		case OPTION_UNICAST:
			Log(Warning) << "Invalid option (" <<ptrOpt->getOptType() << ") received." << LogEnd;
			break;
		default:
			appendDefaultOption(ptrOpt);
			break;
		}
	}
	appendRequestedOptions(duidOpt->getDUID(),rebind->getAddr(),rebind->getIface(),reqOpts);

	// append our DUID
	SmartPtr<TSrvOptServerIdentifier> srvDUID=new TSrvOptServerIdentifier(CfgMgr->getDUID(),this);
	this->Options.append((Ptr*)srvDUID);

	appendAuthenticationOption(duidOpt->getDUID());

	pkt = new char[this->getSize()];
	IsDone = false;
	this->MRT = 0;

	this->send();

}

/** 
* this constructor is used to create REPLY message as a response for RELEASE message
* 
* @param ifaceMgr 
* @param transMgr 
* @param CfgMgr 
* @param AddrMgr 
* @param release 
*/TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
							 SmartPtr<TSrvTransMgr> transMgr, 
							 SmartPtr<TSrvCfgMgr> CfgMgr, 
							 SmartPtr<TSrvAddrMgr> AddrMgr,
							 SmartPtr<TSrvMsgRelease> release)
							 :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
							 release->getIface(),release->getAddr(), REPLY_MSG, 
							 release->getTransID())
{
	this->copyRelayInfo((Ptr*)release);
	this->copyAAASPI((Ptr*)release);
	this->copyRemoteID((Ptr*)release);

	//FIXME:When the server receives a Release message via unicast from a client
	//to which the server has not sent a unicast option, the server
	//discards the Release message and responds with a Reply message
	//containing a Status Code option with value UseMulticast, a Server
	//Identifier option containing the server's DUID, the Client Identifier
	//option from the client message, and no other options.

	SmartPtr<TSrvOptClientIdentifier> clntID;
	SmartPtr<TOpt> opt, subOpt;

	release->firstOption();
	opt = release->getOption(OPTION_SERVERID);
	Options.append(opt);

	release->firstOption();
	opt = release->getOption(OPTION_CLIENTID);
	Options.append(opt);
	clntID=(Ptr*) opt;

	SmartPtr<TAddrClient> client = AddrMgr->getClient(clntID->getDUID());
	if (!client) {
		Log(Warning) << "Received RELEASE from unknown client." << LogEnd;
		IsDone = true;
		return;
	}

	SmartPtr<TSrvCfgIface> ptrIface = SrvCfgMgr->getIfaceByID( this->Iface );
	if (!ptrIface) {
		Log(Crit) << "Msg received through not configured interface. "
			"Somebody call an exorcist!" << LogEnd;
		IsDone = true;
		return;
	}

	appendAuthenticationOption(clntID->getDUID());

	release->firstOption();
	while(opt=release->getOption()) {
		switch (opt->getOptType()) {
	case OPTION_IA_NA: {
		SmartPtr<TSrvOptIA_NA> clntIA = (Ptr*) opt;
		SmartPtr<TSrvOptIAAddress> addr;
		bool anyDeleted=false;

		// does this client has IA? (iaid check)
		SmartPtr<TAddrIA> ptrIA = client->getIA(clntIA->getIAID() );
		if (!ptrIA) {
			Log(Warning) << "No such IA (iaid=" << clntIA->getIAID() << ") found for client:" << *clntID->getDUID() << LogEnd;
			Options.append( new TSrvOptIA_NA(clntIA->getIAID(), 0, 0, STATUSCODE_NOBINDING,"No such IA is bound.",this) );
			continue;
		}

		// if there was DNS Update performed, execute deleting Update
		SPtr<TFQDN> fqdn = ptrIA->getFQDN();
		if (fqdn) {
			this->fqdnRelease(ptrIface, ptrIA, fqdn);
		}

		// let's verify each address
		clntIA->firstOption();
		while(subOpt=clntIA->getOption()) {
			if (subOpt->getOptType()!=OPTION_IAADDR)
				continue;
			addr = (Ptr*) subOpt;
			if (AddrMgr->delClntAddr(clntID->getDUID(), clntIA->getIAID(), addr->getAddr(), false) ) {
				CfgMgr->delClntAddr(this->Iface,addr->getAddr());
				anyDeleted=true;                    
			} else {
				Log(Warning) << "No such binding found: client=" << clntID->getDUID()->getPlain() << ", IA (iaid=" 
					<< clntIA->getIAID() << "), addr="<< addr->getAddr()->getPlain() << LogEnd;
			};
		};

		// send result to the client
		if (!anyDeleted)
		{
			SmartPtr<TSrvOptIA_NA> ansIA(new TSrvOptIA_NA(clntIA->getIAID(), clntIA->getT1(),clntIA->getT2(),this));
			Options.append((Ptr*)ansIA);
			ansIA->addOption(new TSrvOptStatusCode(STATUSCODE_NOBINDING, "Not every address had binding.",this));
		};
		break;
					   }
	case OPTION_IA_TA: {
		SmartPtr<TSrvOptTA> ta = (Ptr*) opt;
		bool anyDeleted = false;
		SmartPtr<TAddrIA> ptrIA = client->getTA(ta->getIAID() );
		if (!ptrIA) {
			Log(Warning) << "No such TA (iaid=" << ta->getIAID() << ") found for client:" << *clntID->getDUID() << LogEnd;
			Options.append( new TSrvOptTA(ta->getIAID(), STATUSCODE_NOBINDING, "No such IA is bound.", this) );
			continue;
		}

		// let's verify each address
		ta->firstOption();
		while ( subOpt = (Ptr*) ta->getOption() ) {
			if (subOpt->getOptType()!=OPTION_IAADDR)
				continue;
			SmartPtr<TSrvOptIAAddress> addr = (Ptr*) subOpt;
			if (AddrMgr->delTAAddr(clntID->getDUID(), ta->getIAID(), addr->getAddr()) ) {
				CfgMgr->delTAAddr(this->Iface);
				anyDeleted=true;                    
			} else {
				Log(Warning) << "No such binding found: client=" << clntID->getDUID()->getPlain() << ", TA (iaid=" 
					<< ta->getIAID() << "), addr="<< addr->getAddr()->getPlain() << LogEnd;
			};
		}

		// send results to the client
		if (!anyDeleted)
		{
			SmartPtr<TSrvOptTA> answerTA = new TSrvOptTA(ta->getIAID(), STATUSCODE_NOBINDING, "Not every address had binding.", this);
			Options.append((Ptr*)answerTA);
		};
		break;
					   }

	case OPTION_IA_PD: {
		SmartPtr<TSrvOptIA_PD> pd = (Ptr*) opt;
		SmartPtr<TSrvOptIAPrefix> prefix;
		bool anyDeleted=false;

		// does this client has PD? (iaid check)
		SmartPtr<TAddrIA> ptrPD = client->getPD( pd->getIAID() );
		if (!ptrPD) {
			Log(Warning) << "No such PD (iaid=" << pd->getIAID() << ") found for client:" << *clntID->getDUID() << LogEnd;
			Options.append( new TSrvOptIA_PD(pd->getIAID(), 0, 0, STATUSCODE_NOBINDING,"No such PD is bound.",this) );
			continue;
		}

		// let's verify each address
		pd->firstOption();
		while(subOpt=pd->getOption()) {
			if (subOpt->getOptType()!=OPTION_IAPREFIX)
				continue;
			prefix = (Ptr*) subOpt;
			if (AddrMgr->delPrefix(clntID->getDUID(), pd->getIAID(), prefix->getPrefix(), false) ) {
				CfgMgr->decrPrefixCount(Iface, prefix->getPrefix());
				anyDeleted=true;                    
			} else {
				Log(Warning) << "PD: No such binding found: client=" << clntID->getDUID()->getPlain() << ", PD (iaid=" 
					<< pd->getIAID() << "), addr="<< prefix->getPrefix()->getPlain() << LogEnd;
			};
		};

		// send result to the client
		if (!anyDeleted)
		{
			SmartPtr<TSrvOptIA_PD> ansPD(new TSrvOptIA_PD(pd->getIAID(), 0, 0, this));
			Options.append((Ptr*)ansPD);
			ansPD->addOption(new TSrvOptStatusCode(STATUSCODE_NOBINDING, "Not every address had binding.",this));
		};
		break;
					   }
	default:
		break;
		}; // switch(...)
	} // while 

	Options.append(new TSrvOptStatusCode(STATUSCODE_SUCCESS,
		"All IAs in RELEASE message were processed.",this));

	pkt = new char[this->getSize()];
	IsDone = false;

	this->MRT=46;
	this->send();
}

// used as RENEW reply
TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
						   SmartPtr<TSrvTransMgr> transMgr, 
						   SmartPtr<TSrvCfgMgr> CfgMgr, 
						   SmartPtr<TSrvAddrMgr> AddrMgr,
						   SmartPtr<TSrvMsgRenew> renew)
						   :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
						   renew->getIface(),renew->getAddr(), REPLY_MSG, renew->getTransID())
{
	this->copyRelayInfo((Ptr*)renew);
	this->copyAAASPI((Ptr*)renew);
	this->copyRemoteID((Ptr*)renew);

	// uncomment this to test REBIND
	//IsDone = true;
	//return;
	// uncomment this to test REBIND

	unsigned long addrCount=0;
	SmartPtr<TOpt> ptrOpt;
	setOptionsReqOptClntDUID((Ptr*)renew);
	if (!duidOpt) {
		Log(Warning) << "RENEW message without client-id option received, message dropped." << LogEnd;
		IsDone = true;
		return;
	}

	renew->firstOption();
	while (ptrOpt = renew->getOption() ) 
	{
		switch (ptrOpt->getOptType()) 
		{
		case OPTION_SERVERID:
			this->Options.append(ptrOpt);
			break;
		case OPTION_IA_NA: {
			SmartPtr<TSrvOptIA_NA> optIA_NA;
			optIA_NA = new TSrvOptIA_NA(CfgMgr, AddrMgr, (Ptr*)ptrOpt, 
				renew->getAddr(), duidOpt->getDUID(),
				renew->getIface(), addrCount, RENEW_MSG, this);
			this->Options.append((Ptr*)optIA_NA);
			break;
						   }
		case OPTION_IA_PD: {
			SPtr<TSrvOptIA_PD> optPD;
			optPD = new TSrvOptIA_PD(CfgMgr, AddrMgr, (Ptr*)ptrOpt,
				renew->getAddr(), duidOpt->getDUID(),
				renew->getIface(), RENEW_MSG, this);
			Options.append( (Ptr*) optPD);
			break;
						   }
		case OPTION_IA_TA:
			Log(Warning) << "TA option present. Temporary addreses cannot be renewed." << LogEnd;
			break;
			//Invalid options in RENEW message
		case OPTION_RELAY_MSG :
		case OPTION_INTERFACE_ID :
		case OPTION_RECONF_MSG:
		case OPTION_IAADDR:
		case OPTION_PREFERENCE:
		case OPTION_RAPID_COMMIT:
		case OPTION_UNICAST:
		case OPTION_STATUS_CODE:
			Log(Warning) << "Invalid option "<<ptrOpt->getOptType()<<" received." << LogEnd;
			break;
		default:
			appendDefaultOption(ptrOpt);
			break;
		}
	}
	appendRequestedOptions(duidOpt->getDUID(),renew->getAddr(),renew->getIface(),reqOpts);

	appendAuthenticationOption(duidOpt->getDUID());

	pkt = new char[this->getSize()];
	IsDone = false;
	this->MRT = 0;
	this->send();
}

/** 
* this constructor is used to construct REPLY for REQUEST message
* 
* @param ifaceMgr 
* @param transMgr 
* @param CfgMgr 
* @param AddrMgr 
* @param request 
*/
TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
						   SmartPtr<TSrvTransMgr> transMgr, 
						   SmartPtr<TSrvCfgMgr> CfgMgr, 
						   SmartPtr<TSrvAddrMgr> AddrMgr,
						   SmartPtr<TSrvMsgRequest> request)
						   :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,
						   request->getIface(),request->getAddr(), REPLY_MSG, request->getTransID())
{
	this->copyRelayInfo((Ptr*)request);
	this->copyAAASPI((Ptr*)request);
	this->copyRemoteID((Ptr*)request);

	SmartPtr<TOpt>       opt;
	SmartPtr<TSrvOptClientIdentifier> optClntID;
	SmartPtr<TDUID>      clntDuid;
	SmartPtr<TIPv6Addr>  clntAddr;
	unsigned int         clntIface;

	opt = request->getOption(OPTION_CLIENTID);
	optClntID = (Ptr*) opt;
	clntDuid  = optClntID->getDUID();
	clntAddr  = request->getAddr();
	clntIface = request->getIface();

	setOptionsReqOptClntDUID((Ptr*)request);
	if (!duidOpt) {
		Log(Warning) << "REQUEST message without client-id option received, message dropped." << LogEnd;
		IsDone = true;
		return;
	}


	// is this client supported?
	if (!CfgMgr->isClntSupported(clntDuid, clntAddr, clntIface)) {
		//No reply for this client 
		Log(Notice) << "Client (DUID=" << clntDuid->getPlain() << ",addr=" << *clntAddr 
			<< ") was rejected due to accept-only or reject-client." << LogEnd;
		IsDone=true;
		return;
	}

	// try to provide answer for all options
	request->firstOption();
	while ( opt = request->getOption() ) {
		switch (opt->getOptType()) {
	case OPTION_SERVERID    : {
		this->Options.append(opt);
		break;
							  }

	case OPTION_IA_TA: {
		SmartPtr<TSrvOptTA> ta;
		ta = new TSrvOptTA(AddrMgr, CfgMgr, (Ptr*) opt, clntDuid, clntAddr,
			clntIface, REQUEST_MSG, this);
		this->Options.append((Ptr*)ta);
		break;
					   }

	case OPTION_IA_PD: {
		SmartPtr<TSrvOptIA_PD> pd;
		pd = new TSrvOptIA_PD(CfgMgr, AddrMgr, (Ptr*) opt, clntAddr, clntDuid, 
			clntIface, REQUEST_MSG, this);
		this->Options.append((Ptr*)pd);
		break;
					   }
	case OPTION_STATUS_CODE :
	case OPTION_RELAY_MSG   :
	case OPTION_PREFERENCE  :
	case OPTION_RECONF_MSG  :
	case OPTION_INTERFACE_ID:
	case OPTION_IAADDR      :
	case OPTION_UNICAST     :
	case OPTION_RAPID_COMMIT:
		Log(Warning) << "Invalid option " << opt->getOptType()<<" received." << LogEnd;
		break;
	case OPTION_FQDN : {
		SmartPtr<TSrvOptFQDN> requestFQDN = (Ptr*) opt;
		SmartPtr<TOptFQDN> anotherFQDN = (Ptr*) opt;
		SmartPtr<TSrvOptFQDN> optFQDN;

		string hint = anotherFQDN->getFQDN();

		SPtr<TIPv6Addr> clntAssignedAddr = SrvAddrMgr->getFirstAddr(clntDuid);
		if (clntAssignedAddr)
			optFQDN = this->prepareFQDN(requestFQDN, clntDuid, clntAssignedAddr, hint, true);
		else
			optFQDN = this->prepareFQDN(requestFQDN, clntDuid, clntAddr, hint, true);
		if (optFQDN) {
			this->Options.append((Ptr*) optFQDN);
		}
		break;
					   }
	case OPTION_VENDOR_OPTS:
		{
			SPtr<TSrvOptVendorSpec> v = (Ptr*) opt;
			appendVendorSpec(clntDuid, clntIface, v->getVendor(), reqOpts);
			//----------添加处理，利用gps数据生成ip地址的  host部分（后64位）-----处理gps-----
			std::string vendor_rly=v->getVendorDataPlain();
			std::string vendor_type_rly, vendor_len_rly, 
				vendor_x_rly, vendor_y_rly, vendor_z_rly;
			vendor_type_rly = vendor_rly.substr(0, 4);
			vendor_len_rly= vendor_rly.substr(4, 4);
			vendor_x_rly= vendor_rly.substr(8, 9);
			vendor_y_rly= vendor_rly.substr(17, 9);
			vendor_z_rly= vendor_rly.substr(26, 6);

			std::string type2clntaddr=clntAddr->getPlain();


			if(vendor_type_rly=="0002")
			{

				ifstream fin1("/var/lib/dibbler/cfgdata/srv/maclist.txt");	
				ifstream fin2("/var/lib/dibbler/cfgdata/srv/gpslist.txt");     //2016-11-07
				if (!fin1||!fin2){
					//cout << "ipv6文件列表不存在" << endl;;
					//exit(1); // terminate with error 
					ipv6_addr2_rly="-1";
				}
				vector<string> vc1, vc2;
				std::string s;
				while (!fin1.eof())
				{
					getline(fin1, s);
					//cout << s << endl;
					vc1.push_back(s);

				}
				while (!fin2.eof())
				{
					getline(fin2, s);
					//cout << s << endl;
					vc2.push_back(s);
				}

				fin1.close();fin2.close();
				std::vector<string>:: iterator it1;
				it1=find(vc1.begin(),vc1.end(),type2clntaddr);
				if(it1==vc1.end())
				{
					ipv6_addr2_rly="-1";
				}

				else
				{
					int a=0;
					a=it1-vc1.begin();

					vendor_rly = vc2[a];
					vendor_x_rly = vendor_rly.substr(0, 9);
					vendor_y_rly = vendor_rly.substr(9, 9);
					vendor_z_rly = vendor_rly.substr(18, 6);
				}
			}
			std::string vendor_xx_rly= vendor_x_rly.substr(3, 6);
			std::string vendor_yy_rly = vendor_y_rly.substr(3, 6);

			int  gps_x_rly, gps_y_rly ,gps_zz_rly;
			// double gps_z;
			gps_x_rly= atoi(vendor_xx_rly.c_str());
			gps_y_rly = atoi(vendor_yy_rly.c_str());
			gps_zz_rly = atoi(vendor_z_rly.c_str());
			// gps_z = ((double)gps_zz )/ 100;
			//--************************** gps 的经纬度和高度已经转为int类型
			std::string x_bin_rly, y_bin_rly, z_bin_rly;
			x_bin_rly = Dec2BinR(gps_x_rly);
			//int xxx = Bin2Dec(x_bin);
			y_bin_rly = Dec2BinR(gps_y_rly);
			z_bin_rly = Dec2BinR(gps_zz_rly);

			std::string x_hex_rly;
			x_hex_rly = Dec2HexR(gps_x_rly);

			for (int i = x_hex_rly.size(); i < 5; i++)
			{

				x_hex_rly =  '0'+ x_hex_rly;

			}
			//std::cout << "经度(16进制): " << x_hex << std::endl;

			//-------*************纬度处理*****************
			std::string y_hex_rly;
			y_hex_rly = Dec2HexR(gps_y_rly);
			for (int i = y_hex_rly.size(); i < 5; i++)
			{

				y_hex_rly = '0' + y_hex_rly;

			}
			std::string z_hex_rly;
			z_hex_rly = Dec2HexR(gps_zz_rly);
			for (int i = z_hex_rly.size(); i < 5; i++)
			{

				z_hex_rly = '0' + z_hex_rly;

			}


			ipv6_type_rly = "1";
			ipv6_addr_rly = ipv6_type_rly + x_hex_rly + y_hex_rly + z_hex_rly;


			for (int k = 0; k < ipv6_addr_rly.size(); k++)
			{
				ipv6_addr2_rly += ipv6_addr_rly[k];
				if (((k +1)% 4 == 0)&&(k!=0)&&(k!=ipv6_addr_rly.size()-1))
				{
					ipv6_addr2_rly = ipv6_addr2_rly + ":";
				}

			}
			//测试host id 是否正确
			//char filename4[]="/home/b1305/ip_host_reply.txt";
			//ofstream fout4(filename4);
			//fout4<<"addr_rly: "<<ipv6_addr_rly<<std::endl;  
			//fout4<<"addr2_rly: "<<ipv6_addr2_rly<<std::endl;  
			//fout4<<"已经生成host -id...reply"<<endl;

			//fout4.close(); 


			/*
			char filename[]="/home/b1305/vendor_spec_reply.txt";
			ofstream fout(filename);
			fout<<"v->getVendor():"<<v->getVendor()<<endl;  
			fout<<"v->getVendorDataPlain():"<<v->getVendorDataPlain()<<endl; 
			fout<<"v->getVendorDataLen():"<<v->getVendorDataLen()<<endl; 
			std::string vendor1=v->getVendorDataPlain();
			unsigned long long  num=0;
			num=atoi(vendor1.c_str());
			fout<<num<<endl;
			fout<<num+1<<endl;

			fout.close();  
			*/


			//Log(Notice) << "server get client vendor...hahaha..." << LogEnd;


			break;
		}
	case OPTION_IA_NA: {

		if(ipv6_addr2_rly!="")
		{
			SmartPtr<TSrvOptIA_NA> optIA;
			optIA = new TSrvOptIA_NA(AddrMgr, CfgMgr, (Ptr*) opt, clntDuid, 
				clntAddr, clntIface, REQUEST_MSG, this,ipv6_addr2_rly);
			this->Options.append((Ptr*)optIA);
		}

		break;
					   }
	default:
		appendDefaultOption(opt);
		break;
		}
	}

	appendRequestedOptions(clntDuid, clntAddr, clntIface, reqOpts);

	appendAuthenticationOption(clntDuid);

	pkt = new char[this->getSize()];
	IsDone = false;
	SmartPtr<TIPv6Addr> ptrAddr;
	this->MRT = 330; 
	this->send();
}

//SOLICIT
TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
						   SmartPtr<TSrvTransMgr> transMgr, 
						   SmartPtr<TSrvCfgMgr> CfgMgr, 
						   SmartPtr<TSrvAddrMgr> AddrMgr,
						   SmartPtr<TSrvMsgSolicit> solicit)
						   :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,solicit->getIface(),
						   solicit->getAddr(),REPLY_MSG,solicit->getTransID())
{
	this->copyRelayInfo((Ptr*)solicit);
	this->copyAAASPI((Ptr*)solicit);
	this->copyRemoteID((Ptr*)solicit);

	SmartPtr<TOpt>       opt;
	SmartPtr<TSrvOptClientIdentifier> optClntID;
	SmartPtr<TDUID>      clntDuid;
	SmartPtr<TIPv6Addr>  clntAddr;
	unsigned int         clntIface;

	opt = solicit->getOption(OPTION_CLIENTID);
	optClntID = (Ptr*) opt;
	clntDuid  = optClntID->getDUID();
	clntAddr  = solicit->getAddr();
	clntIface = solicit->getIface();

	setOptionsReqOptClntDUID((Ptr*)solicit);
	if (!duidOpt) {
		Log(Warning) << "SOLICIT message without client-id option received, message dropped." << LogEnd;
		IsDone = true;
		return;
	}

	// include our DUID 
	SmartPtr<TSrvOptServerIdentifier> srvDUID=new TSrvOptServerIdentifier(CfgMgr->getDUID(),this);
	this->Options.append((Ptr*)srvDUID);

	// include rapid commit
	SmartPtr<TSrvOptRapidCommit> optRapidCommit = new TSrvOptRapidCommit(this);
	this->Options.append((Ptr*)optRapidCommit);

	// is this client supported?
	if (!CfgMgr->isClntSupported(clntDuid, clntAddr, clntIface)) {
		//No reply for this client 
		Log(Notice) << "Client (DUID=" << clntDuid->getPlain() << ",addr=" << *clntAddr 
			<< ") was rejected due to accept-only or reject-client." << LogEnd;
		IsDone=true;
		return;
	}

	//So if we can do something for this client at least set configuration
	//parameters - let's do  option by option - try to answer to it
	solicit->firstOption();
	while ( opt = solicit->getOption() ) 
	{
		switch (opt->getOptType()) 
		{
		case OPTION_SERVERID    :
			Log(Warning) << "Solicit message contains ServerID option. Rejecting message. " << LogEnd;
			IsDone = true;
			return;
		case OPTION_IA_NA       : {
			SmartPtr<TSrvOptIA_NA> optIA_NA;
			optIA_NA = new TSrvOptIA_NA(AddrMgr, CfgMgr, (Ptr*) opt, clntDuid, clntAddr, 
				clntIface, REQUEST_MSG,this,ipv6_addr2_rly);
			this->Options.append((Ptr*)optIA_NA);
			break;
								  }
		case OPTION_IA_TA: {
			SmartPtr<TSrvOptTA> ta;
			ta = new TSrvOptTA(AddrMgr, CfgMgr, (Ptr*) opt, clntDuid, clntAddr,
				clntIface, REQUEST_MSG, this);
			this->Options.append((Ptr*)ta);
			break;
						   }
		case OPTION_STATUS_CODE : 
		case OPTION_RELAY_MSG   :
		case OPTION_PREFERENCE  :
		case OPTION_RECONF_MSG  :
		case OPTION_INTERFACE_ID:
		case OPTION_IAADDR      :
		case OPTION_UNICAST     :
			Log(Warning) << "Invalid option type("
				<<opt->getOptType()<<") received." << LogEnd;
			break;
		case OPTION_RAPID_COMMIT:
			Log(Info) << "SOLICIT with RAPID-COMMIT received." << LogEnd;
			break;
		default:
			appendDefaultOption(opt);
			break;
		}
	}
	appendRequestedOptions(clntDuid, clntAddr, clntIface, reqOpts);

	appendAuthenticationOption(clntDuid);

	pkt = new char[this->getSize()];
	IsDone = false;
	SmartPtr<TIPv6Addr> ptrAddr;
	this->MRT = 330; 
	this->send();
}

// INFORMATION-REQUEST answer
TSrvMsgReply::TSrvMsgReply(SmartPtr<TSrvIfaceMgr> ifaceMgr, 
						   SmartPtr<TSrvTransMgr> transMgr, 
						   SmartPtr<TSrvCfgMgr> CfgMgr, 
						   SmartPtr<TSrvAddrMgr> AddrMgr,
						   SmartPtr<TSrvMsgInfRequest> question)
						   :TSrvMsg(ifaceMgr,transMgr,CfgMgr,AddrMgr,question->getIface(),
						   question->getAddr(),REPLY_MSG,question->getTransID())
{
	this->copyRelayInfo((Ptr*)question);
	this->copyAAASPI((Ptr*)question);
	this->copyRemoteID((Ptr*)question);

	SmartPtr<TOpt> ptrOpt;
	setOptionsReqOptClntDUID((Ptr*)question);

	Log(Debug) << "Received INF-REQUEST requesting " << this->showRequestedOptions(this->reqOpts) << "." << LogEnd;

	question->firstOption();
	while (ptrOpt = question->getOption() ) 
	{
		switch (ptrOpt->getOptType()) 
		{

		case OPTION_RELAY_MSG   :
		case OPTION_SERVERID    :
		case OPTION_INTERFACE_ID:
		case OPTION_STATUS_CODE : 
		case OPTION_IAADDR      :
		case OPTION_PREFERENCE  :
		case OPTION_UNICAST     :
		case OPTION_RECONF_MSG  :
		case OPTION_IA_NA       : 
		case OPTION_IA_TA       :
		case OPTION_AAAAUTH     :
		case OPTION_KEYGEN      :
			Log(Warning) << "Invalid option " << ptrOpt->getOptType() <<" received." << LogEnd;
			break;
		default:
			this->appendDefaultOption(ptrOpt);
			break;
		}
	}
	SPtr<TDUID> duid;
	if (duidOpt)
		duid = duidOpt->getDUID();
	else
		duid = new TDUID();

	if (appendRequestedOptions(duid, question->getAddr(),question->getIface(),reqOpts)) {
		// include our DUID
		SmartPtr<TSrvOptServerIdentifier> srvDUID=new TSrvOptServerIdentifier(CfgMgr->getDUID(),this);
		this->Options.append((Ptr*)srvDUID);

		appendAuthenticationOption(duid);

		pkt = new char[this->getSize()];
		IsDone = false;
		this->MRT = 330; // FIXME: 
		this->send();
	} else {
		Log(Warning) << "No options to answer in INF-REQUEST, so REPLY will not be send." << LogEnd;
		IsDone=true;
	}
}

void TSrvMsgReply::doDuties() {
	IsDone = true;
}

unsigned long TSrvMsgReply::getTimeout() {
	unsigned long diff = now() - this->FirstTimeStamp;
	if (diff>SERVER_REPLY_CACHE_TIMEOUT)
		return 0;
	return SERVER_REPLY_CACHE_TIMEOUT-diff;
}

bool TSrvMsgReply::check() {
	/* not used on the server side */
	return false;
}

void TSrvMsgReply::appendDefaultOption(SmartPtr<TOpt> ptrOpt) {
	int opt = ptrOpt->getOptType();
	switch(opt)
	{
	case OPTION_CLIENTID :
		this->Options.append(ptrOpt);
		break;
	case OPTION_ORO:
		//we found it at the beginning of function
		break;
	case OPTION_ELAPSED_TIME :
		//Ignore - BE PATIENT MY CLIENT!!!
		break;
	default:
		// all other options set in OPTION REQUEST
		if (!reqOpts->isOption(opt))
			reqOpts->addOption(opt);
		break;
	}
}

/** 
* finds CLIENT_DUID and OPTIONREQUEST in options
* 
* @param msg - parent message
*/
void TSrvMsgReply::setOptionsReqOptClntDUID(SmartPtr<TMsg> msg)
{
	reqOpts= SmartPtr<TSrvOptOptionRequest>();
	// remember client's DUID
	duidOpt = (Ptr*) msg->getOption(OPTION_CLIENTID);
	//remember requested option in order to add number of "hint" options
	//wich are included in packet but not in Request Option
	//if Request option wasn't included by client - create new one
	//in which number of "hint" options could be stored
	this->reqOpts=(Ptr*)msg->getOption(OPTION_ORO);
	//If there is no option Request it will ba added
	if (!reqOpts)
		this->reqOpts=new TSrvOptOptionRequest(this);
}

TSrvMsgReply::~TSrvMsgReply()
{

}

string TSrvMsgReply::getName() {
	return "REPLY";
}

