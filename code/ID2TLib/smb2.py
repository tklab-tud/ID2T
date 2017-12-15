from scapy.packet import *
from scapy.fields import *
from scapy.layers.netbios import NBTSession



class SMB2_SYNC_Header(Packet):
    namez = "SMB2Negociate Protocol Response Header"
    fields_desc = [StrFixedLenField("Start","\xfeSMB",4),
                   LEShortField("StructureSize",64),
                   LEShortField("CreditCharge", 0),
                   LEIntField("Status",0),
                   LEShortField("Command",0),
                   LEShortField("CreditResponse",0),
                   LEIntField("Flags",1),
                   LEIntField("NextCommand",0),
                   LELongField("MessageID",0),
                   LEIntField("Reserved",0),
                   LEIntField("TreeID",0x0),
                   LELongField("SessionID",1),
                   LELongField("Signature1",0),
                   LELongField("Signature2",1)]

#No Support of Security Buffer , Padding or Dialect Revision 0x0311
class SMB2_Negotiate_Protocol_Response(Packet):
    namez = "SMB2Negociate Protocol Response"
    fields_desc = [LEShortField("StructureSize" , 65),
                   LEShortField("SecurityMode", 0),
                   LEShortField("DialectRevision", 0x0),
                   LEShortField("NegotiateContentCount/Reserved", 0),
                   StrFixedLenField("ServerGuid" , "" ,16 ),
                   LEIntField("Capabilities", 0),
                   LEIntField("MaxTransactSize",0),
                   LEIntField("MaxReadSize",0),
                   LEIntField("MaxWriteSize",0),
                   LELongField("SystemTime",0),
                   LELongField("ServerStartTime",0),
                   LEShortField("SecurityBufferOffset",0),
                   LEShortField("SecurityBufferLength",0),
                   LEIntField("NegotiateContextOffset/Reserved2",0)]



bind_layers( NBTSession,                           SMB2_SYNC_Header, )
bind_layers( SMB2_SYNC_Header, SMB2_Negotiate_Protocol_Response, )