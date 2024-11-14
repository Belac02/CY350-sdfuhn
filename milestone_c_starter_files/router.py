import time
import socket
import logging
from pdu import IPHeader, LSADatagram, HTTPDatagram
from graph import Graph

class Router:
    def __init__(self, router_id: str, router_interfaces: dict, direct_connections: dict):
        """
        Initializes a Router object.

        Args:
            router_id (str): Unique identifier for the router.
            router_interfaces (dict): A dictionary of router interfaces in the form {interface_name: (source_ip, dest_ip)}.
            direct_connections (dict): A dictionary of directly connected networks in the form {network: (cost, interface)}.

        Raises:
            Exception: If a socket fails to initialize.
        """
        self.router_id = router_id  
        self.router_interfaces = router_interfaces
        self.direct_connections = direct_connections
        self.lsa_seq_num = 0
        self.interface_sockets = {}
        
        # Initialize sockets for each interface
        for interface, (source, _) in self.router_interfaces.items():
            try:
                int_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                int_socket.bind((source, 0))
                int_socket.setblocking(False)
                self.interface_sockets[interface] = int_socket
            except Exception as e:
                logging.error(f'Error creating socket for {interface}: {e}')

        # Create a socket for receiving datagrams
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        receive_socket.bind(('0.0.0.0', 0))
        receive_socket.setblocking(False)
        self.interface_sockets['rec'] = receive_socket

        # Initialize LSA database, timers, and forwarding table
        self.router_lsa_num = {}
        self.lsdb = {}
        self.lsa_timer = time.time()
        self.forwarding_table = {}

        # Configure logging
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)s - %(message)s',
                            handlers=[logging.FileHandler('network_app_router.log', mode='w')]
                            )

        self.initialize_lsdb()

    def initialize_lsdb(self):
        """
        Initializes the Link-State Database (LSDB) with the router's direct connections.
        
        The LSDB is a data structure that holds information about the router's directly connected networks
        and the cost of reaching them.
        
        Returns:
            None
        """

        ### INSERT CODE HERE ###
        # Store the destination, cost, and interface for each direct connection of the router in the LSDB
        self.lsdb[self.router_id] = [(dst, cost, iface) for dst, (cost, iface) in self.direct_connections.items()]

    def update_lsdb(self, adv_rtr: str, lsa: str):
        """
        Updates the Link-State Database (LSDB) with new information from a received LSA.

        Args:
            adv_rtr (str): The advertising router's ID.
            lsa (str): The LSA data as a string, where each line contains the neighbor, cost, and interface information.

        Returns:
            None
        """
        lsa = [tuple(line.split(',')) for line in lsa.split('\r\n')]
        self.lsdb[adv_rtr] = [(neighbor.strip(), int(cost.strip()), interface.strip()) for neighbor, cost, interface in lsa]

    def send_initial_lsa(self):
        """
        Broadcasts the initial Link-State Advertisement (LSA) containing the router's direct connections to all interfaces.

        Returns:
            None

        Logs:
            Logs the sending of the initial LSA.
        """
        for interface, (source, dest) in self.router_interfaces.items():
            int_socket = self.interface_sockets[interface]
            formatted_lsa_data = [f'{neighbor}, {cost}, {interface}' for neighbor, cost, interface in self.lsdb[self.router_id]]
            new_datagram = LSADatagram(source_ip=source, dest_ip='224.0.0.5', adv_rtr=self.router_id, lsa_seq_num=self.lsa_seq_num, lsa_data='\r\n'.join(formatted_lsa_data))
            int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
        logging.info(f'{self.router_id} has sent the initial LSA.')

    def forward_lsa(self, lsa_datagram: LSADatagram, lsa_int: str):
        """
        Forwards a received LSA to all interfaces except the one on which it was received.

        Args:
            lsa_datagram (LSADatagram): The received LSA datagram to be forwarded.
            lsa_int (str): The interface on which the LSA was received.

        Returns:
            None

        Logs:
            Logs the forwarding of the LSA to the destination.
        
        Exceptions:
            Logs any exceptions that occur during forwarding.
        """
        time.sleep(1) # Make sure all initial LSAs are sent before forwarding an LSA
        for interface in self.router_interfaces:
            if interface != lsa_int and lsa_datagram.adv_rtr != self.router_id:
                source, dest = self.router_interfaces[interface]
                int_socket = self.interface_sockets[interface]
                new_datagram = LSADatagram(source_ip=source, dest_ip='224.0.0.5', adv_rtr=lsa_datagram.adv_rtr, lsa_seq_num=lsa_datagram.lsa_seq_num, lsa_data=lsa_datagram.lsa_data)
                try:
                    int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
                    logging.info(f'{self.router_id}: LSA forwarded to {dest}.')
                except Exception as e:
                    logging.error(f'Error forwarding LSA: {e}')

    def process_link_state_advertisement(self, lsa: bytes, interface: str):
        """
        Processes a received Link-State Advertisement (LSA) and updates the LSDB. If the LSA contains new information, 
        the router broadcasts the LSA to its other interfaces.

        Args:
            lsa (bytes): The received LSA in byte form.
            interface (str): The interface on which the LSA was received.

        Returns:
            None

        Raises:
            None
        """

        ### INSERT CODE HERE ###
        lsa_packet = LSADatagram.from_bytes(lsa)
        if (self.router_id != lsa_packet.adv_rtr) and (lsa_packet.adv_rtr not in self.router_lsa_num.keys() or self.router_lsa_num[lsa_packet.adv_rtr] < lsa_packet.lsa_seq_num):
            self.lsa_timer = time.time()
            self.router_lsa_num[lsa_packet.adv_rtr] = lsa_packet.lsa_seq_num
            self.update_lsdb(lsa_packet.adv_rtr, lsa_packet.lsa_data)
            self.forward_lsa(lsa_packet, interface)

    def forward_datagram(self, dgram: bytes):
        """
        Forwards an HTTP datagram to the appropriate next hop based on the forwarding table.

        Args:
            dgram (bytes): The datagram received as raw bytes.

        Returns:
            None

        Logs:
            Logs the process of forwarding the datagram to the appropriate next hop.

        Raises:
            Exception: Logs any errors during the forwarding process.
        """

        ### INSERT CODE HERE ###
        http_dgram = HTTPDatagram.from_bytes(dgram)
        if http_dgram.next_hop in [connection[0] for connection in self.router_interfaces.values()]:
            dest_ip_binary = ''.join(f'{int(octet):08b}' for octet in http_dgram.ip_daddr.split('.'))
            longest_prefix = None
            max_length = -1
            for network in self.forwarding_table.keys():
                if '/' in network:
                    network_add, prefix_length = network.split('/')
                    prefix_length = int(prefix_length)
                    network_addr_binary = ''.join(f'{int(octet):08b}'for octet in network_add.split('.'))
                    matching_bits = 0
                    for i in range(prefix_length):
                        if network_addr_binary[i] == dest_ip_binary[i]:
                            matching_bits += 1
                        else:
                            break
                    
                    if matching_bits > max_length:
                        longest_prefix = network
                        max_length = matching_bits

        fwd_int = self.forwarding_table[longest_prefix][0] if longest_prefix else None
        fwd_socket = self.interface_sockets[fwd_int]
        fwd_dgram = HTTPDatagram(source_ip=http_dgram.ip_saddr, dest_ip=http_dgram.ip_daddr, source_port=http_dgram.source_port, dest_port=http_dgram.dest_port, seq_num=http_dgram.seq_num, ack_num=http_dgram.ack_num, flags=http_dgram.flags, window_size=http_dgram.window_size, next_hop=self.router_interfaces[fwd_int][1], data=http_dgram.data)
        fwd_dgram_bytes = fwd_dgram.to_bytes()
        fwd_socket.sendto(fwd_dgram_bytes, (self.router_interfaces[fwd_int][1], 0))
 
    def run_route_alg(self):
        """
        Runs Dijkstra's shortest path algorithm to calculate the shortest paths to all nodes
        in the network and updates the forwarding table based on the LSDB.

        Returns:
            None

        Raises:
            None
        """
        ### INSERT CODE HERE ###
        graph = Graph()
        for node, neighbors in self.lsdb.items():
            for neighbor, cost, interface in neighbors:
                graph.add_edge(node, neighbor, cost, interface)
        ## Initialization for Djikstra's algorithm

        # Create a set of visited nodes that has the start node only (initially)
        visited_nodes = {self.router_id}
        # Set the distance to all known nodes to infinity, except for:
        #       - the start node, which is initialized to 0
        #       - the nodes directly connected to the start node should have distance equal to their cost
        distances = {node: float('inf') for node in graph.nodes}
        distances[self.router_id] = 0
        # Additionally, store the full path from the start node to each node. Initially, the path to each node
        #       is an empty list since no path has been calculated yet.
        paths = {node: [] for node in graph.nodes}

        # Update costs, paths for direct connections
        for neighbor, cost, interface in graph.nodes[self.router_id]:
            distances[neighbor] = cost
            paths[neighbor] =[(self.router_id, interface)]

        ## Dijkstra's algorithm
        # While not all nodes have been processed (i.e., while N_prime does not include all nodes in the graph)
        while visited_nodes != graph.nodes:
            unvisited_nodes = [node for node in graph.nodes if node not in visited_nodes]
            if not unvisited_nodes:
                break
            next_node = min(unvisited_nodes, key=distances.get)
            visited_nodes.add(next_node)
            # For all neighbors of node 'w'
            for neighbor, cost, interface in graph.nodes[next_node]:
                # Only consider neighbors that have not been processed yet (i.e., not in N_prime)
                if neighbor not in visited_nodes:
                    newdistance = distances[next_node] + cost
                    if newdistance < distances[neighbor]:
                        distances[neighbor] = newdistance
                        paths[neighbor] = paths[next_node] + [(neighbor, interface)]
        ## Construct the forwarding table for each node in the graph.
        # For each node, store:
        # 1. The outgoing interface used to reach the node, which is found by accessing the first hop in 'paths[node]' (if a path exists).
        # 2. The shortest known distance to that node from the source, stored in 'D[node]'.
        # If there is no path to the node, the interface is set to None.
        # The resulting forwarding table maps each node to a tuple: (interface, shortest distance).
        self.forwarding_table = {}
        for node in graph.nodes:
            if distances[node] != float('inf') and len(paths[node]) > 0:
                self.forwarding_table[node] = (paths[node][0][1], distances[node])
            else:
                self.forwarding_table[node] = (None, 0)

    def process_datagrams(self):
        """
        Receives, processes, and forwards incoming datagrams or LSAs. It updates the LSDB and forwarding table as needed,
        and then forwards datagrams to their correct next hop.

        Returns:
            None

        Logs:
            Logs the content of the LSDB and forwarding table.
        """
        while time.time() - self.lsa_timer < 5:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, address = self.interface_sockets[interface].recvfrom(1024)
                    new_datagram = IPHeader.from_bytes(new_datagram_bytes)
                    if new_datagram.ip_daddr == '224.0.0.5' and address[0] in [connection[1] for connection in self.router_interfaces.values()]:
                        self.process_link_state_advertisement(new_datagram_bytes, interface)
                except Exception:
                    continue

        self.run_route_alg()
        time.sleep(1)
        start_time = time.time()
        while time.time() - start_time < 10:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, _ = self.interface_sockets[interface].recvfrom(1024)
                    self.forward_datagram(new_datagram_bytes)
                except Exception:
                    continue

        logging.info(f'{self.router_id} LSDB: {self.lsdb}')
        logging.info(f'{self.router_id} Forwarding Table: {self.forwarding_table}')
        self.shutdown()

    def shutdown(self):
        """
        Shuts down the router by closing all open sockets.

        Returns:
            None

        Logs:
            Logs the shutdown process of the router.
        """
        # Close all interface sockets
        for interface in self.interface_sockets.keys():
            try:
                self.interface_sockets[interface].close()
            except Exception as e:
                logging.error(f'Error closing socket for {interface}: {e}')

# Example usage
if __name__ == "__main__":
    r1_interfaces = {
        'Gi0/1': ('127.0.0.254', '127.0.0.1'), 
        'Gi0/2': ('127.248.0.1', '127.248.0.2'),
        'Gi0/3': ('127.248.4.1', '127.248.4.2')
    }
    
    r1_direct_connections = {
        '127.0.0.0/24': (0, 'Gi0/1'),
        '2.2.2.2': (3, 'Gi0/2'), 
        '3.3.3.3': (9, 'Gi0/3')
    }
    
    R1 = Router('1.1.1.1', r1_interfaces, r1_direct_connections)
    R1.shutdown()
