import pyparsing as pp


class QueryParser:
    def __init__(self):
        # TODO: allow lists as input, like: ipaddress(macaddress in [1,2,3])
        extractor = pp.Keyword("random") ^ pp.Keyword("first") ^ pp.Keyword("last")
        # Valid selectors - except "avg", because not all attributes can be combined with it
        selector_no_avg = pp.Keyword("most_used") ^ pp.Keyword("least_used") ^ pp.Keyword("all")
        attributes_no_avg = pp.Keyword("ipaddress") ^ pp.Keyword("macaddress") ^ pp.Keyword("portnumber") ^\
                            pp.Keyword("protocolname") ^ pp.Keyword("winsize") ^ pp.Keyword("ipclass")

        attributes_avg = pp.Keyword("ttlvalue") ^ pp.Keyword("mssvalue") ^\
                         pp.Keyword("pktssent") ^ pp.Keyword("pktsreceived") ^ pp.Keyword("mss") ^\
                         pp.Keyword("kbytesreceived") ^ pp.Keyword("kbytessent")

        attributes_all = attributes_no_avg ^ attributes_avg
        simple_selector_query = (selector_no_avg + pp.Suppress("(") + attributes_all + pp.Suppress(")")) ^\
                                (pp.Keyword("avg") + pp.Suppress("(") + attributes_avg + pp.Suppress(")"))

        param_selectors = pp.Keyword("ipaddress").setParseAction(pp.replaceWith("ipaddress_param")) ^\
                          pp.Keyword("macaddress").setParseAction(pp.replaceWith("macaddress_param"))

        operators = pp.Literal("<=") ^ pp.Literal("<") ^ pp.Literal("=") ^\
                    pp.Literal(">=") ^ pp.Literal(">") ^ pp.CaselessLiteral("in")
        expr = pp.Forward()
        comparison = pp.Group(attributes_all + operators + (pp.Word(pp.alphanums + ".:") ^ expr))
        parameterized_query = param_selectors + pp.Suppress("(") + pp.Group(pp.delimitedList(comparison)) + pp.Suppress(")")

        all_selector_queries = (simple_selector_query ^ parameterized_query)
        extractor_selector_query = extractor + pp.Suppress("(") + all_selector_queries + pp.Suppress(")")

        named_query = (extractor_selector_query ^ all_selector_queries)
        expr << pp.Group(named_query)
        self.full_query = named_query + pp.Suppress(";")

    def parse_query(self, querystring: str) -> pp.ParseResults:
        return self.full_query.parseString(querystring)
