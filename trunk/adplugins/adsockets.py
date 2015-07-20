import logging
import addatastructs.adutils as utils
import volatility.plugins.sockets as socketsref
import volatility.plugins.connscan as connscan
import volatility.plugins.netscan as netscan
import addatastructs.process_pb2 as datastructs

SOCKET_STATE = \
{
    'CLOSED':      1,
    'LISTENING':   2,
    'SYN_SENT':    3,
    'SYN_RCVD':    4,
    'ESTABLISHED': 5,
    'FIN_WAIT1':   6,
    'FIN_WAIT2':   7,
    'CLOSE_WAIT':  8,
    'CLOSING':     9,
    'LAST_ACK':   10,
    'TIME_WAIT':  11,
    'DELETE_TCB': 12
}

def _convert_socket_state(state):
    if state in SOCKET_STATE.keys():
        return int(SOCKET_STATE[str(state)])
    else:
        return 0



def getSocketsFactory(profile):
    if (profile.metadata.get("os") == "windows" and profile.metadata.get("major") == 5):
        return getSocketsForWindowsXP
    else:
        return getSockets

def getSocketsForWindowsXP(config,address_space):
    sockets = dict()
    try:
        for tcp_obj in connscan.ConnScan(config).calculate():
            pid = int(tcp_obj.Pid)
            if pid in sockets:
                socketObj = sockets[pid].Socket.add(resultitemtype=16)
            else:
                socketObjList = datastructs.Open_Sockets_ListType()
                socketObj = socketObjList.Socket.add(resultitemtype=16)
                sockets[pid] = socketObjList

            if type(tcp_obj.LocalPort) is str:
                socketObj.Port=0
            else:
                socketObj.Port=int(tcp_obj.LocalPort)

            if type(tcp_obj.RemotePort) is str:
                socketObj.RemotePort=0
            else:
                socketObj.RemotePort = int(tcp_obj.RemotePort)
            socketObj.LocalAddress = utils._utf8_encode(tcp_obj.LocalIpAddress)
            socketObj.RemoteAddress = utils._utf8_encode(tcp_obj.RemoteIpAddress)
            #socketObj.set_Proto(_utf8_encode(sock.Protocol))
            socketObj.State = 0
            socketObj.RealState = _convert_socket_state("ESTABLISHED")
            socketObj.FromMemory = ""
            socketObj.PID = pid

        for sock in socketsref.Sockets(config).calculate():
            pid = int(sock.Pid)
            if pid in sockets.keys():
                socketObj = sockets[pid].Socket.add(resultitemtype=16)
            else:
                socketObjList = datastructs.Open_Sockets_ListType()
                socketObj = socketObjList.Socket.add(resultitemtype=16)
                sockets[pid] = socketObjList
            socketObj.LocalAddress = utils._utf8_encode(sock.LocalIpAddress)
            socketObj.FromMemory = ""
            socketObj.PID = int(sock.Pid)
            socketObj.State = 0
            socketObj.RealState = _convert_socket_state("LISTENING")
            if type(tcp_obj.LocalPort) is str:
                socketObj.Port = 0
            else:
                socketObj.Port = int(sock.LocalPort)
            socketObj.Proto = utils._utf8_encode(sock.Protocol)

    except Exception, e:
        logging.exception(e)
    return sockets


def getSockets(config,kernel_addr_space):
    sockets = dict()
    try:
      for net_object, protocol, laddr, lport, raddr, rport, state in netscan.Netscan(config).calculate():
          owner = net_object.Owner.dereference_as('_EPROCESS')

          pid = int(owner.UniqueProcessId)
          if pid in sockets:
              socketObj = sockets[pid].Socket.add(resultitemtype = 16)
          else:
              socketObjList = datastructs.Open_Sockets_ListType()
              socketObj = socketObjList.Socket.add(resultitemtype = 16)
              sockets[pid] = socketObjList

          if type(lport) is str:
              socketObj.Port = 0
          else:
              socketObj.Port = int(lport)
          socketObj.LocalAddress = utils._utf8_encode(laddr or "")
          if type(rport) is str:
              socketObj.RemotePort = 0
          else:
              socketObj.RemotePort = int(rport)
          socketObj.RemoteAddress = utils._utf8_encode(raddr)
          socketObj.Proto = utils._utf8_encode(protocol)
          socketObj.State = 0
          socketObj.RealState = _convert_socket_state(state)
          socketObj.ProcessName = utils._utf8_encode(owner.ImageFileName)
          socketObj.Path = utils._utf8_encode(owner.Peb.ProcessParameters.ImagePathName or "")
          socketObj.FromMemory = ""
          socketObj.PID = pid
    except Exception, e:
      logging.exception(e)
    return sockets
