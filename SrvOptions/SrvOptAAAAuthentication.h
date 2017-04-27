/*
 * Dibbler - a portable DHCPv6
 *
 * author: Michal Kowalczuk <michal@kowalczuk.eu>
 *
 * released under GNU GPL v2 only licence
 *
 * $Id: SrvOptAAAAuthentication.h,v 1.2 2008-08-29 00:07:35 thomson Exp $
 *
 * $Log: SrvOptAAAAuthentication.h,v $
 * Revision 1.2  2008-08-29 00:07:35  thomson
 * Temporary license change(GPLv2 or later -> GPLv2 only)
 *
 * Revision 1.1  2008-02-25 20:42:46  thomson
 * Missing new AUTH files added.
 *
 *
 */

#ifndef SRVOPTAAAAUTHENTICATION_H
#define SRVOPTAAAAUTHENTICATION_H

#include "OptAAAAuthentication.h"

class TSrvOptAAAAuthentication : public TOptAAAAuthentication
{
 public:
    TSrvOptAAAAuthentication(char * buf,  int n, TMsg* parent);
  
    TSrvOptAAAAuthentication(TMsg* parent);
    bool doDuties();
};

#endif
