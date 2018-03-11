import pyparsing as pp


class QueryParser:
    def __init__(self):
        extractor = pp.Keyword("random") ^ pp.Keyword("first") ^ pp.Keyword("last")
        selector = pp.Keyword("most_used") ^ pp.Keyword("least_used") ^ pp.Keyword("avg") ^ pp.Keyword("all")
        attribute = pp.Keyword("ipaddress") ^ pp.Keyword("macaddress") ^ pp.Keyword("portnumber") ^ pp.Keyword("protocolname") ^ pp.Keyword("ttlvalue") ^ pp.Keyword("mssvalue") ^ pp.Keyword("winsize") ^ pp.Keyword("ipclass") ^ pp.Keyword("pktssent") ^ pp.Keyword("pktsreceived") ^ pp.Keyword("mss") ^ pp.Keyword("kbytesreceived") ^ pp.Keyword("kbytessent")
        simple_selector_query = selector + pp.Suppress("(") + attribute + pp.Suppress(")")

        param_selectors = pp.Keyword("ipaddress").setParseAction(pp.replaceWith("ipaddress_param")) ^ pp.Keyword("macaddress").setParseAction(pp.replaceWith("macaddress_param"))
        operators = pp.Literal("=") ^ pp.Literal("<=") ^ pp.Literal("<") ^ pp.Literal(">=") ^ pp.Literal(">")
        expr = pp.Forward()
        comparison = pp.Group(attribute + operators + (pp.Word(pp.alphanums + ".:") ^ expr))
        parameterized_query = param_selectors + pp.Suppress("(") + pp.Group(pp.delimitedList(comparison)) + pp.Suppress(")")
        # parameterized_query = param_selectors + pp.Suppress("(") + comparison + pp.Suppress(")")

        all_selector_queries = (simple_selector_query ^ parameterized_query)
        extractor_selector_query = extractor + pp.Suppress("(") + all_selector_queries + pp.Suppress(")")

        named_query = (extractor_selector_query ^ all_selector_queries)
        expr << pp.Group(named_query)
        self.full_query = named_query + pp.Suppress(";")

    def parse_query(self, querystring):
        return self.full_query.parseString(querystring)
