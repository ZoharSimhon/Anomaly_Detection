import networkx as nx
import matplotlib.pyplot as plt
import pyshark
import time 
from queue import Queue
# from node2vec import Node2Vec # for graph embedding

# def graphEmbedding(graph: nx.DiGraph):
#     # Precompute probabilities and generate walks - **ON WINDOWS ONLY WORKS WITH workers=1**
#     node2vec = Node2Vec(graph, dimensions=128, walk_length=40, num_walks=100, workers=1)
#     # Embed nodes
#     model = node2vec.fit(window=10, min_count=1)
#     # Retrieve node embeddings
#     node_ids = model.wv.index_to_key  # list of node IDs
#     node_embeddings = model.wv.vectors
#     print(node_ids)
#     print(node_embeddings)

# from gensim.models import Word2Vec

# def graph_embedding(graph):
#     # Generate random walks
#     walks = [list(map(str, walk)) for walk in nx.random_walks.RandomWalk(graph).walks()]

#     # Train Word2Vec model
#     model = Word2Vec(sentences=walks, vector_size=128, window=10, min_count=1, workers=1)

#     # Get embeddings for all nodes
#     embeddings = {node: model.wv[str(node)] for node in graph.nodes()}

#     return embeddings


def removeRow(q: Queue, graph: nx.DiGraph):
    src_ip, dst_ip = q.get()
    graph[src_ip][dst_ip]['weight'] -= 1
    if graph[src_ip][dst_ip]['weight'] == 0:
        graph.remove_edge(src_ip, dst_ip)
        # remove the isolated vertices from the graph
        # if not graph.degree[src_ip]:
        #     graph.remove_node(src_ip)
        # if not graph.degree[dst_ip]:
        #     graph.remove_node(dst_ip)

def create_directed_graph_from_pcap(pcap_file, sliding_window_size, num_of_rows = 500):
    graph = nx.DiGraph()
    prev_time = time.time()
    prev_sniff_time = None
    q = Queue(maxsize=sliding_window_size)
    cap = pyshark.FileCapture(pcap_file)
    for i, packet in enumerate(cap):
        
        if i == num_of_rows:
            return graph

        if q.full():
            removeRow(q, graph)

        print(time.time() - prev_time)
        if 2 <= time.time() - prev_time:
            visualize_directed_graph(graph)
            prev_time = time.time()
        if hasattr(packet, 'ip'):
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            q.put((src_ip, dst_ip))        
            if graph.has_edge(src_ip, dst_ip):
                graph[src_ip][dst_ip]['weight'] += 1
            else:
                graph.add_edge(src_ip, dst_ip, weight=1)
        if hasattr(packet, 'sniff_time'):
            if prev_sniff_time:
                time_delta = float(packet.sniff_time.timestamp()) - prev_sniff_time
                time.sleep(time_delta/8)
            prev_sniff_time = float(packet.sniff_time.timestamp())
    return graph

def visualize_directed_graph(graph: nx.DiGraph):
    plt.clf()
    # edge_labels = {(src, dst): graph[src][dst]['weight'] for src, dst in graph.edges}
    
    pos = nx.spring_layout(graph, seed=5)  # You can use different layouts based on your preference
    nx.draw(graph, pos, with_labels=True, font_weight='bold', arrowsize=15, connectionstyle='arc3, rad = 0.1')
    # pos=nx.drawing.nx_agraph.graphviz_layout(
    #     graph,
    #     prog='dot',
    #     args='-Grankdir=LR',
    #     # seed=5
    # )
    # nx.draw(
    #     graph,
    #     node_size=2000,
    #     node_color='#0000FF',
    #     arrowsize=50,
    #     with_labels=True,
    #     labels={n: n for n in graph.nodes},
    #     font_color='#FFFFFF',
    #     font_size=35,
    #     pos=pos
    # )
    
    edge_labels = {}
    for src, dst, d in graph.edges(data=True):
        if (dst,src) in graph.edges:
            if pos[src][0] > pos[dst][0]:
                edge_labels[(src,dst)] = f'{d["weight"]}\n\n{graph.edges[(dst,src)]["weight"]}'
        else:
            edge_labels[(src, dst)] = graph[src][dst]['weight']
            
            
    # edge_labels = dict([((src, dst,), f'{d["weight"]}\n\n{graph.edges[(dst,src)]["weight"]}')
                # for src, dst, d in graph.edges(data=True) if pos[src][0] > pos[dst][0] and (dst,src) in graph.edges])

    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_color='black')

    plt.ion()
    plt.show()
    plt.pause(2)

if __name__ == '__main__':
    
    # graph representation
    pcap_file_path = 'Thursday-WorkingHours.pcap'
    graph = create_directed_graph_from_pcap(pcap_file_path, 500, 2000)
    
    # graph embedding
    # embeddings = graph_embedding(graph)

    # # Print embeddings for the first few nodes
    # for node, embedding in embeddings.items():
    #     print(f"Node {node}: {embedding}")
    
    # dynamic clustering
    
    # anomaly detection 
