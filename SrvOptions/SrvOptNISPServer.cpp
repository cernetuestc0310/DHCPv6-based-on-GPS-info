/*
 * Dibbler - a portable DHCPv6
 *
 * authors: Tomasz Mrugalski <thomson@klub.com.pl>
 *          Marek Senderski <msend@o2.pl>
 *
 * released under GNU GPL v2 only licence
 *
 * $Id: SrvOptNISPServer.cpp,v 1.2 2008-08-29 00:07:37 thomson Exp $
 *
 * $Log: SrvOptNISPServer.cpp,v $
 * Revision 1.2  2008-08-29 00:07:37  thomson
 * Temporary license change(GPLv2 or later -> GPLv2 only)
 *
 * Revision 1.1  2004-11-02 01:30:54  thomson
 * Initial version.
 *
 */

#include "SrvOptNISPServer.h"
#include "DHCPConst.h"

TSrvOptNISPServers::TSrvOptNISPServers(List(TIPv6Addr) lst, TMsg* parent)
    :TOptAddrLst(OPTION_NISP_SERVERS, lst, parent) {

}

TSrvOptNISPServers::TSrvOptNISPServers(char* buf, int size, TMsg* parent)
    :TOptAddrLst(OPTION_NISP_SERVERS, buf,size, parent) {
    
}

bool TSrvOptNISPServers::doDuties() {    
    return true;
}
