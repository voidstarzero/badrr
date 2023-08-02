import collections  # for defaultdict


class RecordCache:
    def __init__(self):
        self._cache = collections.defaultdict(list)

    def add(self, rname: str, rdata: str) -> None:
        self._cache[rname].append(rdata)

    def contains(self, rname: str) -> bool:
        return rname in self._cache

    def get(self, rname: str) -> list[str]:
        return self._cache[rname]
