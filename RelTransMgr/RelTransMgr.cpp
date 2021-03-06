/*
 * Dibbler - a portable DHCPv6
 *
 * authors: Tomasz Mrugalski <thomson@klub.com.pl>
 *          Marek Senderski <msend@o2.pl>
 *
 * released under GNU GPL v2 only licence
 *
 * $Id: RelTransMgr.cpp,v 1.20 2008-08-29 00:07:33 thomson Exp $
 *
 */

#define MAX_PACKET_LEN 1452
#define RELAY_FORW_MSG_LEN 36

#include "RelTransMgr.h"
#include "RelCfgMgr.h"
#include "RelIfaceMgr.h"
#include "RelOptInterfaceID.h"
#include "RelOptEcho.h"
#include "RelOptGeneric.h"
#include "Logger.h"

TRelTransMgr::TRelTransMgr(TCtx * ctx, string xmlFile)
{
    // remember context
    this->Ctx = ctx;
    this->IsDone = false; // TransMgr is certainly not done yet. We're just getting started
    this->XmlFile = xmlFile;

    // for each interface in CfgMgr, create socket (in IfaceMgr)
    SmartPtr<TRelCfgIface> confIface;
    this->Ctx->CfgMgr->firstIface();
    while (confIface=this->Ctx->CfgMgr->getIface()) {
	if (!this->openSocket(confIface)) {
	    this->IsDone = true;
	    break;
	}
    }
}

/*
 * opens proper (multicast or unicast) socket on interface 
 */
bool TRelTransMgr::openSocket(SmartPtr<TRelCfgIface> cfgIface) {

    SmartPtr<TIfaceIface> iface = this->Ctx->IfaceMgr->getIfaceByID(cfgIface->getID());
    if (!iface) {
	Log(Crit) << "Unable to find " << cfgIface->getName() << "/" << cfgIface->getID()
		  << " interface in the IfaceMgr." << LogEnd;
	return false;
    }

    SmartPtr<TIPv6Addr> srvUnicast = cfgIface->getServerUnicast();
    SmartPtr<TIPv6Addr> clntUnicast = cfgIface->getClientUnicast();
    SmartPtr<TIPv6Addr> addr;

    if (cfgIface->getServerMulticast() || srvUnicast) {

	iface->firstGlobalAddr();
	addr = iface->getGlobalAddr();
	if (!addr) {
	    Log(Warning) << "No global address defined on the " << iface->getFullName() << " interface."
			 << " Trying to bind link local address, but expect troubles with relaying." << LogEnd;
	    iface->firstLLAddress();
	    addr = new TIPv6Addr(iface->getLLAddress());
	}
	Log(Notice) << "Creating srv unicast (" << addr->getPlain() << ") socket on the "
		    << iface->getName() << "/" << iface->getID() << " interface." << LogEnd;
	if (!iface->addSocket(addr, DHCPSERVER_PORT, true, false)) {
	    Log(Crit) << "Proper socket creation failed." << LogEnd;
	    return false;
	}
    }

    if (cfgIface->getClientMulticast()) {
	addr = new TIPv6Addr(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, true);
	Log(Notice) << "Creating clnt multicast (" << addr->getPlain() << ") socket on the "
		    << iface->getName() << "/" << iface->getID() << " interface." << LogEnd;
	if (!iface->addSocket(addr, DHCPSERVER_PORT, true, false)) {
	    Log(Crit) << "Proper socket creation failed." << LogEnd;
	    return false;
	}
    }

    if (clntUnicast) {
	addr = new TIPv6Addr(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, true);
	Log(Notice) << "Creating clnt unicast (" << clntUnicast->getPlain() << ") socket on the "
		    << iface->getName() << "/" << iface->getID() << " interface." << LogEnd;
	if (!iface->addSocket(clntUnicast, DHCPSERVER_PORT, true, false)) {
	    Log(Crit) << "Proper socket creation failed." << LogEnd;
	    return false;
	}
    }

    return true;
}


/**
 * relays normal (i.e. not server replies) messages to defined servers
 */
void TRelTransMgr::relayMsg(SmartPtr<TRelMsg> msg)
{	
    static char buf[MAX_PACKET_LEN];
    int offset = 0;
    int bufLen;
    int hopCount = 0;
    if (!msg->check()) {
	Log(Warning) << "Invalid message received." << LogEnd;
        return;
    }
    
    if (msg->getDestAddr()) {
	this->relayMsgRepl(msg);
	return;
    }

    if (msg->getType() == RELAY_FORW_MSG) {
	hopCount = msg->getHopCount()+1;
    }

    // prepare message
    SmartPtr<TIfaceIface> iface = this->Ctx->IfaceMgr->getIfaceByID(msg->getIface());
    SmartPtr<TIPv6Addr> addr;

    // store header
    buf[offset++] = RELAY_FORW_MSG;
    buf[offset++] = hopCount;

    // store link-addr 
    iface->firstGlobalAddr();
    addr = iface->getGlobalAddr();
    if (!addr) {
	Log(Warning) << "Interface " << iface->getFullName() << " does not have global address." << LogEnd;
	addr = new TIPv6Addr("::", true);
    }
    addr->storeSelf(buf+offset);
    offset += 16;

    // store peer-addr
    addr = msg->getAddr();
    addr->storeSelf(buf+offset);
    offset += 16;

    SmartPtr<TRelCfgIface> cfgIface;
    cfgIface = this->Ctx->CfgMgr->getIfaceByID(msg->getIface());
    TRelOptInterfaceID ifaceID(cfgIface->getInterfaceID(), 0);

    if (Ctx->CfgMgr->getInterfaceIDOrder()==REL_IFACE_ID_ORDER_BEFORE)
    {
	// store InterfaceID option
	ifaceID.storeSelf(buf + offset);
	offset += ifaceID.getSize();
	Log(Debug) << "Interface-id option added before relayed message." << LogEnd;
    }

    // store relay msg option
    *(short*)(buf+offset) = htons(OPTION_RELAY_MSG);
    offset+=2;
    *(short*)(buf+offset) = htons(msg->getSize());
    offset+=2;
    bufLen = msg->storeSelf(buf+offset);
    offset += bufLen;

    if (Ctx->CfgMgr->getInterfaceIDOrder()==REL_IFACE_ID_ORDER_AFTER)
    {
	// store InterfaceID option
	ifaceID.storeSelf(buf + offset);
	offset += ifaceID.getSize();
	Log(Debug) << "Interface-id option added after relayed message." << LogEnd;
    }

    if (Ctx->CfgMgr->getInterfaceIDOrder()==REL_IFACE_ID_ORDER_NONE)
    {
	Log(Warning) << "Interface-id option not added (interface-id-order omit used in relay.conf). "
		     << "That is a debugging feature and violates RFC3315. Use with caution." << LogEnd;
    }

    SPtr<TRelOptRemoteID> remoteID = Ctx->CfgMgr->getRemoteID();
    if (remoteID) {
	remoteID->storeSelf(buf+offset);
	offset += remoteID->getSize();
	Log(Debug) << "Appended RemoteID with " << remoteID->getVendorDataLen() << "-byte long data (option length=" 
		   << remoteID->getSize() << ")." << LogEnd;
    }

    SPtr<TRelOptEcho> echo = Ctx->CfgMgr->getEcho();
    if (echo) {
	echo->storeSelf(buf+offset);
	offset += echo->getSize();
	Log(Debug) << "Appended EchoRequest option with ";

	int i=0;
	char tmpBuf[256];
	for (i=0;i<255;i++)
	    tmpBuf[i] = 255-i;

	for (int i=0; i<echo->count(); i++) {
	    int code = echo->getReqOpt(i);
	    SPtr<TRelOptGeneric> gen = new TRelOptGeneric(code, tmpBuf, 4, 0);
	    gen->storeSelf(buf+offset);
	    offset += gen->getSize();
	    Log(Cont) << code << " ";
	}
	Log(Cont) << " opt(s)." << LogEnd;
    }

    this->Ctx->CfgMgr->firstIface();
    while (cfgIface = this->Ctx->CfgMgr->getIface()) {
	if (cfgIface->getServerUnicast()) {
	    Log(Notice) << "Relaying encapsulated " << msg->getName() << " message on the " << cfgIface->getFullName()
			<< " interface to unicast (" << cfgIface->getServerUnicast()->getPlain() << ") address, port " 
			<< DHCPSERVER_PORT << "." << LogEnd;

	    if (!this->Ctx->IfaceMgr->send(cfgIface->getID(), buf, offset, cfgIface->getServerUnicast(), DHCPSERVER_PORT)) {
		Log(Error) << "Failed to send data to server unicast address." << LogEnd;
	    }
					   
	}
	if (cfgIface->getServerMulticast()) {
	    addr = new TIPv6Addr(ALL_DHCP_SERVERS, true);
	    Log(Notice) << "Relaying encapsulated " << msg->getName() << " message on the " << cfgIface->getFullName()
			<< " interface to multicast (" << addr->getPlain() << ") address, port " 
			<< DHCPSERVER_PORT << "." << LogEnd;
	    if (!this->Ctx->IfaceMgr->send(cfgIface->getID(), buf, offset, addr, DHCPSERVER_PORT)) {
		Log(Error) << "Failed to send data to server multicast address." << LogEnd;
	    }
	}
    }

    // save DB state regardless of action taken
    this->Ctx->CfgMgr->dump();
}	

void TRelTransMgr::relayMsgRepl(SmartPtr<TRelMsg> msg) {
    int port;
    SmartPtr<TRelCfgIface> cfgIface = this->Ctx->CfgMgr->getIfaceByInterfaceID(msg->getDestIface());
    if (!cfgIface) {
	Log(Error) << "Unable to relay message: Invalid interfaceID value:" << msg->getDestIface() << LogEnd;
	return;
    }

    SmartPtr<TIfaceIface> iface = this->Ctx->IfaceMgr->getIfaceByID(cfgIface->getID());
    SmartPtr<TIPv6Addr> addr = msg->getDestAddr();
    static char buf[MAX_PACKET_LEN];
    int bufLen;

    if (!iface) { 
	Log(Warning) << "Unable to find interface with interfaceID=" << msg->getDestIface()
		     << LogEnd;
	return;
    }

    bufLen = msg->storeSelf(buf);
    if (msg->getType() == RELAY_REPL_MSG)
	port = DHCPSERVER_PORT;
    else
	port = DHCPCLIENT_PORT;
    Log(Notice) << "Relaying decapsulated " << msg->getName() << " message on the " << iface->getFullName()
		<< " interface to the " << addr->getPlain() << ", port " << port << "." << LogEnd;

    if (!this->Ctx->IfaceMgr->send(iface->getID(), buf, bufLen, addr, port)) {
	Log(Error) << "Failed to decapsulated data." << LogEnd;
    }
    
}

void TRelTransMgr::shutdown() {
    IsDone = true;
}

bool TRelTransMgr::isDone() {
    return this->IsDone;
}

bool TRelTransMgr::doDuties() {
    return 0;
}

char* TRelTransMgr::getCtrlAddr() {
	return this->ctrlAddr;
}

int  TRelTransMgr::getCtrlIface() {
	return this->ctrlIface;
}

void TRelTransMgr::dump() {
    std::ofstream xmlDump;
    xmlDump.open(this->XmlFile.c_str());
    xmlDump << *this;
    xmlDump.close();
}

TRelTransMgr::~TRelTransMgr() {
    Log(Debug) << "RelTransMgr cleanup." << LogEnd;
}


ostream & operator<<(ostream &s, TRelTransMgr &x)
{
    s << "<TRelTransMgr>" << endl;
    s << "<!-- RelTransMgr dumps are not implemented yet -->" << endl;
    s << "</TRelTransMgr>" << endl;
    return s;
}
