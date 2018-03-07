import scapy.packet as packet
import scapy.fields as field
import scapy.layers.netbios as netbios


class SMB2_SYNC_Header(packet.Packet):
    namez = "SMB2Negociate Protocol Response Header"
    fields_desc = [field.StrFixedLenField("Start", "\xfeSMB", 4),
                   field.LEShortField("StructureSize", 64),
                   field.LEShortField("CreditCharge", 0),
                   field.LEIntField("Status", 0),
                   field.LEShortField("Command", 0),
                   field.LEShortField("CreditResponse", 0),
                   field.LEIntField("Flags", 0),
                   field.LEIntField("NextCommand", 0),
                   field.LELongField("MessageID", 0),
                   field.LEIntField("Reserved", 0),
                   field.LEIntField("TreeID", 0x0),
                   field.LELongField("SessionID", 0),
                   field.LELongField("Signature1", 0),
                   field.LELongField("Signature2", 0)]


# No Support of Security Buffer , Padding or Dialect Revision 0x0311
class SMB2_Negotiate_Protocol_Response(packet.Packet):
    namez = "SMB2Negociate Protocol Response"
    fields_desc = [field.LEShortField("StructureSize", 65),
                   field.LEShortField("SecurityMode", 0),
                   field.LEShortField("DialectRevision", 0x0),
                   field.LEShortField("NegotiateContentCount/Reserved", 0),
                   field.StrFixedLenField("ServerGuid", "", 16),
                   field.LEIntField("Capabilities", 0),
                   field.LEIntField("MaxTransactSize", 0),
                   field.LEIntField("MaxReadSize", 0),
                   field.LEIntField("MaxWriteSize", 0),
                   field.LELongField("SystemTime", 0),
                   field.LELongField("ServerStartTime", 0),
                   field.LEShortField("SecurityBufferOffset", 0),
                   field.LEShortField("SecurityBufferLength", 0),
                   field.StrLenField("SecurityBlob", "", length_from=lambda x: x.ByteCount + 16),
                   field.LEIntField("NegotiateContextOffset/Reserved2", 0)]


packet.bind_layers(netbios.NBTSession, SMB2_SYNC_Header, )
packet.bind_layers(SMB2_SYNC_Header, SMB2_Negotiate_Protocol_Response, )
