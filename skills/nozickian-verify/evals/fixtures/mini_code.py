def shortest_path_nonnegative(graph, source, target):
    """Return the shortest path distance in a directed graph with nonnegative edge weights."""
    import heapq
    pq = [(0, source)]
    dist = {source: 0}
    while pq:
        d, u = heapq.heappop(pq)
        if u == target:
            return d
        if d != dist[u]:
            continue
        for v, w in graph.get(u, []):
            if w < 0:
                raise ValueError("negative edge weight")
            nd = d + w
            if nd < dist.get(v, float('inf')):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return float('inf')
