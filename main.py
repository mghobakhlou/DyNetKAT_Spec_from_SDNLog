import pyshark
import json

def openflow_v1_packets(pcap_file):
    
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter='openflow_v1')
        # print(cap[0].tcp.srcport, cap[0].tcp.dstport)
    except FileNotFoundError:
        print(f"Couldn't find the file: {pcap_file}")
        return [],[]
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return [],[]

    

    packets_info = []  # List of tuples --> Each tuple: (device, port)
    
    # print(cap[1].openflow_v1.get_field_value('openflow.port_no'))
    # print(cap[1].openflow_v1.openflow_port_name.all_fields)
    # print(cap[1].openflow_v1.openflow_1_0_type)
    # print(cap[1].openflow_v1.get_field_value('openflow_datapath_id'))

    TOPO = []

    important_fields = ["openflow_1_0.type", "openflow.in_port", "openflow.eth_src",
                        "openflow.eth_dst", "openflow.dl_vlan", "openflow.ofp_match.dl_type", "openflow.ofp_match.nw_proto", 
                        "openflow.ofp_match.source_addr", "openflow.ofp_match.dest_addr", "openflow.ofp_match.source_port",
                        "openflow.ofp_match.dest_port", "openflow.command", "openflow.reason", "openflow.priority", "eth.src", "eth.dst",
                        "openflow.action_typ", "ip.proto", "ip.src", "ip.dst"]
    
    for packet in cap:        
        # packet.pretty_print()
        if hasattr(packet, 'openflow_v1'):
            packet_info = {}
            
            # 6:  Type: OFPT_FEATURES_REPLY (6)
            # 10: Type: OFPT_PACKET_IN (10)
            # 13: Type: OFPT_PACKET_OUT (13)
            # 14: Type: OFPT_FLOW_MOD (14)

            if int(packet.openflow_v1.openflow_1_0_type) in [6,10,13,14]:
                if int(packet.openflow_v1.openflow_1_0_type) == 6:
                    # print(packet.tcp.srcport)
                    switch_cotroller_port = packet.tcp.srcport
                    field = 'openflow_datapath_id'
                    field_value = packet.openflow_v1.get_field_value(field)
                    # print(field_value)
                    # packet_info[field] = field_value
                    for (port_name,port_number) in zip(packet.openflow_v1.openflow_port_name.all_fields,packet.openflow_v1.openflow_port_no.all_fields):
                        if len(port_name.get_default_value()) < 6:   # switch port name checking 
                            TOPO.append((port_name.get_default_value(), field_value ,[switch_cotroller_port,port_number.get_default_value()]))
                                        # (switch_name, datapath_id, list_of_ports)
                            packet_info[(port_name.get_default_value(), field_value)] = [switch_cotroller_port, port_number.get_default_value()]
                                        # tuple(switch_name, datapath_id): list_of_ports
                        else: 
                            TOPO.append((port_name.get_default_value(),[port_number.get_default_value()]))
                                            # (Host_name, list_of_ports)
                            packet_info[port_name.get_default_value()] = [port_number.get_default_value()]
                                            # Host_name: list_of_ports
                    # print(packet_info)        
                # elif int(packet.openflow_v1.openflow_1_0_type) == 14:
                #     switch_cotroller_port = packet.tcp.dstport
                #     for device_info in TOPO:
                #         if len(device_info) == 3 and switch_cotroller_port in device_info[2]:
                #             packet_info["openflow_datapath_id"] = device_info[1]

                #     for field in packet.openflow_v1._all_fields:
                #         if field in important_fields:
                #             field_value = packet.openflow_v1.get_field_value(field)
                #             packet_info[field] = field_value   
                    
                else:
                    # switch_cotroller_port = packet.tcp.dstport
                    for device_info in TOPO:
                        if (len(device_info) == 3) and (packet.tcp.srcport in device_info[2] or packet.tcp.dstport in device_info[2]):
                            packet_info["openflow_datapath_id"] = device_info[1]    


                    for field in packet.openflow_v1._all_fields:
                        if field in important_fields:
                            field_value = packet.openflow_v1.get_field_value(field)
                            packet_info[field] = field_value
                

                # for i in range(len(packets_info)):
                if not packet_info in packets_info:
                    packets_info.append(packet_info)
                # print(packet_info)

    print("TOPO: ", TOPO)
    print("Done: openflow_v1_packets function")
    return TOPO, packets_info


def write_topo(topology, path):

    all_openflow_messages = open(path, "w")

    

    all_openflow_messages.write("TOPOLOGY: \n")
    # for i in range(len(topology)):
    #     all_openflow_messages.write("Device: " + str(topology[i][0]) + " , Port_Number: " + str(topology[i][1])+ "\n")
    for device_info in topology:
        if (len(device_info) == 3):
            all_openflow_messages.write("Device: " + str(device_info[0]) + " ,datapath_id: "+ str(device_info[1])
                                         + " ,Port_Number: " + str(device_info[2])+ "\n")
        else:
            all_openflow_messages.write("Device: " + str(device_info[0]) + " ,Port_Number: " + str(device_info[1])+ "\n")



def write_log(openflow_packets, path):

    all_openflow_messages = open(path, "w")


    for idx, packet in enumerate(openflow_packets, 1):
        all_openflow_messages.write(f"\nPacket {idx}:\n")
        # print(f"Packet {idx}:")
        for field, value in packet.items():
            # print(f"{field}: {value}")
            all_openflow_messages.write(f"{field}: {value}\n")
        all_openflow_messages.write("\n----------\n")


def extract_DyNetKAT(topology, openflow_packets):

    dynetkat_specification = {"Init" : ""}

    for i in range(len(topology)):
        if i == 0:
            dynetkat_specification["Init"] = dynetkat_specification["Init"] + str(topology[i][0]) + "_0"
        else: 
            dynetkat_specification["Init"] = dynetkat_specification["Init"] + "||" + str(topology[i][0]) + "_0"

        # dynetkat_specification[str(topology[i][0])] = ""

    

    switch_iteration = 0

    # openflow_packets[1:] ----> Ignore first packet ---> feature reply

    for idx, packet in enumerate(openflow_packets[1:], 1):
        # print(f"Packet {idx}:")
        try:
            if int(packet["openflow_1_0.type"]) == 10:
                # print("packet_in")
                TODO = 0
            elif int(packet["openflow_1_0.type"]) == 13:
                # print("packet_out")
                TODO = 0 
            elif int(packet["openflow_1_0.type"]) == 14:
                datapapth_id = packet["openflow_datapath_id"]
                for device_info in topology:
                    if datapapth_id == device_info[1]:
                        switch_name = device_info[0]
                
                dynetkat_specification[switch_name+"_"+str(switch_iteration)] = ""
                # print("flow_mod")
                for field, value in packet.items():
                    # print(f"{field}: {value}")
                    # if field in ["openflow.in_port", "openflow.eth_src", "openflow.eth_dst", "openflow.dl_vlan"]:
                    if field in ["openflow.eth_src", "openflow.eth_dst"]:
                        dynetkat_specification[switch_name+"_"+str(switch_iteration)] =  dynetkat_specification[switch_name+"_"+str(switch_iteration)] + f"({field}: {value})."
                    # elif field in ["openflow.ofp_match.dl_type", "openflow.ofp_match.source_addr", "openflow.ofp_match.dest_addr","openflow.ofp_match.source_port", "openflow.ofp_match.dest_port"]:
                    elif field in ["openflow.ofp_match.source_addr", "openflow.ofp_match.dest_addr","openflow.ofp_match.source_port", "openflow.ofp_match.dest_port"]:
                        dynetkat_specification[switch_name+"_"+str(switch_iteration)] =  dynetkat_specification[switch_name+"_"+str(switch_iteration)] + f"({field} <- {value})."
                
                
                dynetkat_specification[switch_name+"_"+str(switch_iteration)] =  "(" + dynetkat_specification[switch_name+"_"+str(switch_iteration)][:-1] + ");" + switch_name+"_"+str(switch_iteration)
                dynetkat_specification[switch_name+"_"+str(switch_iteration)] = dynetkat_specification[switch_name+"_"+str(switch_iteration)] + " OPLUS " + "CONNECTIONUP_CHANNEL?1;" + switch_name+"_"+str(switch_iteration+1) 
                
                switch_iteration += 1
        except KeyError:
            print("KeyError")
    

    print(json.dumps(dynetkat_specification, indent = 4))





if __name__ == "__main__":
    
    # pcapng_file_path = '/home/mohammadreza/test/data/openflowONLY_2switch_2hostPERswitch_h1h3ok_Oct14.pcapng'
    pcapng_file_path = '/home/mohammadreza/test/data/openflowONLY_3Host_h1h2OK_log_Sep25.pcapng'
    topology, openflow_packets = openflow_v1_packets(pcapng_file_path)
    
    topo_write_path = "/home/mohammadreza/test/Project_Code/topo.txt"
    write_topo(topology, topo_write_path)

    log_write_path = "/home/mohammadreza/test/Project_Code/imp_messages_TOPOLOGYandOpenflow2.txt"
    write_log(openflow_packets,log_write_path)

    extract_DyNetKAT(topology,openflow_packets)
    



'''  Doc

TOPO is list of tuples
                    - len of each tuple for switch is 3  --> (switch_name, datapath_id, list_of_ports)
                    - len of each tuple for switch is 2  --> (Host_name, list_of_ports)



'''