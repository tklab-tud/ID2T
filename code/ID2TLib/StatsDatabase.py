import os.path
import re
import sqlite3
import sys
from random import randint


def dict_gen(curs: sqlite3.Cursor):
    """
    Generates a dictionary of a sqlite3.Cursor object by fetching the query's results.
    Taken from Python Essential Reference by David Beazley.
    """
    field_names = [d[0] for d in curs.description]
    while True:
        rows = curs.fetchmany()
        if not rows:
            return
        for row in rows:
            yield dict(zip(field_names, row))


class StatsDatabase:
    def __init__(self, db_path: str):
        """
        Creates a new StatsDatabase.

        :param db_path: The path to the database file
        """
        self.existing_db = os.path.exists(db_path)
        self.database = sqlite3.connect(db_path)
        self.cursor = self.database.cursor()

        # If DB not existing, create a new DB scheme
        if self.existing_db:
            print('Located statistics database at: ', db_path)
        else:
            print('Statistics database not found. Creating new database at: ', db_path)

    def get_file_info(self):
        """
        Retrieves general file statistics from the database. This includes:

        - packetCount           : Number of packets in the PCAP file
        - captureDuration       : Duration of the packet capture in seconds
        - timestampFirstPacket  : Timestamp of the first captured packet
        - timestampLastPacket   : Timestamp of the last captured packet
        - avgPacketRate         : Average packet rate
        - avgPacketSize         : Average packet size
        - avgPacketsSentPerHost : Average number of packets sent per host
        - avgBandwidthIn        : Average incoming bandwidth
        - avgBandwidthOut       : Average outgoing bandwidth

        :return: a dictionary of keys (see above) and their respective values
        """
        return [r for r in dict_gen(
            self.cursor.execute('SELECT * FROM file_statistics'))][0]

    def get_db_exists(self):
        """
        :return: True if the database was already existent, otherwise False
        """
        return self.existing_db

    @staticmethod
    def _get_selector_keywords():
        """
        :return: a list of selector keywords
        """
        return ['most_used', 'least_used', 'avg', 'all']

    @staticmethod
    def _get_parametrized_selector_keywords():
        """
        :return: a list of parameterizable selector keywords
        """
        return ['ipaddress', 'macaddress']

    @staticmethod
    def _get_extractor_keywords():
        """

        :return: a list of extractor keywords
        """
        return ['random', 'first', 'last']

    def get_all_named_query_keywords(self):
        """

        :return: a list of all named query keywords, used to identify named queries
        """
        return (
            self._get_selector_keywords() + self._get_parametrized_selector_keywords() + self._get_extractor_keywords())

    @staticmethod
    def get_all_sql_query_keywords():
        """
        :return: a list of all supported SQL keywords, used to identify SQL queries
        """
        return ["select", "insert"]

    def _process_user_defined_query(self, query_string: str, query_parameters: tuple = None):
        """
        Takes as input a SQL query query_string and optional a tuple of parameters which are marked by '?' in the query
        and later substituted.

        :param query_string: The query to execute
        :param query_parameters: The tuple of parameters to inject into the query
        :return: the results of the query
        """
        if query_parameters is not None:
            self.cursor.execute(query_string, query_parameters)
        else:
            self.cursor.execute(query_string)
        self.database.commit()
        return self.cursor.fetchall()

    def get_field_types(self, *table_names):
        """
        Creates a dictionary whose keys are the fields of the given table(s) and whose values are the appropriate field
        types, like TEXT for strings and REAL for float numbers.

        :param table_names: The name of table(s)
        :return: a dictionary of {field_name : field_type} for fields of all tables
        """
        dic = {}
        for table in table_names:
            self.cursor.execute("PRAGMA table_info('%s')" % table)
            results = self.cursor.fetchall()
            for field in results:
                dic[field[1].lower()] = field[2]
        return dic

    def named_query_parameterized(self, keyword: str, param_op_val: list):
        """
        Executes a parameterizable named query.

        :param keyword: The query to be executed, like ipaddress or macadress
        :param param_op_val: A list consisting of triples with (parameter, operator, value)
        :return: the results of the executed query
        """
        named_queries = {
            "ipaddress": "SELECT DISTINCT ip_statistics.ipAddress from ip_statistics INNER JOIN ip_mac, ip_ttl, ip_ports, ip_protocols ON ip_statistics.ipAddress=ip_mac.ipAddress AND ip_statistics.ipAddress=ip_ttl.ipAddress AND ip_statistics.ipAddress=ip_ports.ipAddress AND ip_statistics.ipAddress=ip_protocols.ipAddress WHERE ",
            "macaddress": "SELECT DISTINCT macAddress from ip_mac WHERE "}
        query = named_queries.get(keyword)
        field_types = self.get_field_types('ip_mac', 'ip_ttl', 'ip_ports', 'ip_protocols', 'ip_statistics', 'ip_mac')
        conditions = []
        for key, op, value in param_op_val:
            # this makes sure that TEXT fields are queried by strings,
            # e.g. ipAddress=192.168.178.1 --is-converted-to--> ipAddress='192.168.178.1'
            if field_types.get(key) == 'TEXT':
                if not str(value).startswith("'") and not str(value).startswith('"'):
                    value = "'" + value + "'"
            # this replacement is required to remove ambiguity in SQL query
            if key == 'ipAddress':
                key = 'ip_mac.ipAddress'
            conditions.append(key + op + str(value))

        where_clause = " AND ".join(conditions)
        query += where_clause
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def _process_named_query(self, query_param_list):
        """
        Executes a named query.

        :param query_param_list: A query list consisting of (keyword, params), e.g. [(most_used, ipAddress), (random,)]
        :return: the result of the query
        """
        # Definition of SQL queries associated to named queries
        named_queries = {
            "most_used.ipaddress": "SELECT ipAddress FROM ip_statistics WHERE (pktsSent+pktsReceived) == (SELECT MAX(pktsSent+pktsReceived) from ip_statistics) LIMIT 1",
            "most_used.macaddress": "SELECT * FROM (SELECT macAddress, COUNT(*) as occ from ip_mac GROUP BY macAddress ORDER BY occ DESC) WHERE occ=(SELECT COUNT(*) as occ from ip_mac GROUP BY macAddress ORDER BY occ DESC LIMIT 1)",
            "most_used.portnumber": "SELECT portNumber, COUNT(portNumber) as cntPort FROM ip_ports GROUP BY portNumber HAVING cntPort=(SELECT MAX(cntPort) from (SELECT portNumber, COUNT(portNumber) as cntPort FROM ip_ports GROUP BY portNumber))",
            "most_used.protocolname": "SELECT protocolName, COUNT(protocolCount) as countProtocols FROM ip_protocols GROUP BY protocolName HAVING countProtocols=(SELECT COUNT(protocolCount) as cnt FROM ip_protocols GROUP BY protocolName ORDER BY cnt DESC LIMIT 1)",
            # Aidmar
            #"most_used.ttlvalue": "SELECT ttlValue FROM ip_ttl WHERE ttlCount == (SELECT MAX(ttlCount) FROM ip_ttl)",
            "most_used.ttlvalue": "SELECT ttlValue FROM ip_ttl GROUP BY ttlValue ORDER BY SUM(ttlCount) DESC LIMIT 1",
            "most_used.mssvalue": "SELECT mssValue FROM tcp_mss_dist GROUP BY mssValue ORDER BY SUM(mssCount) DESC LIMIT 1",
            "most_used.winsize": "SELECT winSize FROM tcp_syn_win GROUP BY winSize ORDER BY SUM(winCount) DESC LIMIT 1",
            "most_used.ipclass": "SELECT ipClass FROM ip_statistics GROUP BY ipClass ORDER BY COUNT(*) DESC LIMIT 1",

            "least_used.ipaddress": "SELECT ipAddress FROM ip_statistics WHERE (pktsSent+pktsReceived) == (SELECT MIN(pktsSent+pktsReceived) from ip_statistics)",
            "least_used.macaddress": "SELECT * FROM (SELECT macAddress, COUNT(*) as occ from ip_mac GROUP BY macAddress ORDER BY occ ASC) WHERE occ=(SELECT COUNT(*) as occ from ip_mac GROUP BY macAddress ORDER BY occ ASC LIMIT 1)",
            "least_used.portnumber": "SELECT portNumber, COUNT(portNumber) as cntPort FROM ip_ports GROUP BY portNumber HAVING cntPort=(SELECT MIN(cntPort) from (SELECT portNumber, COUNT(portNumber) as cntPort FROM ip_ports GROUP BY portNumber))",
            "least_used.protocolname": "SELECT protocolName, COUNT(protocolCount) as countProtocols FROM ip_protocols GROUP BY protocolName HAVING countProtocols=(SELECT COUNT(protocolCount) as cnt FROM ip_protocols GROUP BY protocolName ORDER BY cnt ASC LIMIT 1)",
            "least_used.ttlvalue": "SELECT ttlValue FROM ip_ttl WHERE ttlCount == (SELECT MIN(ttlCount) FROM ip_ttl)",
            "avg.pktsreceived": "SELECT avg(pktsReceived) from ip_statistics",
            "avg.pktssent": "SELECT avg(pktsSent) from ip_statistics",
            "avg.kbytesreceived": "SELECT avg(kbytesReceived) from ip_statistics",
            "avg.kbytessent": "SELECT avg(kbytesSent) from ip_statistics",
            "avg.ttlvalue": "SELECT avg(ttlValue) from ip_ttl",
            #"avg.mss": "SELECT avg(mss) from tcp_mss_dist",
            "all.ipaddress": "SELECT ipAddress from ip_statistics",
            "all.ttlvalue": "SELECT DISTINCT ttlValue from ip_ttl",
            #"all.mss": "SELECT DISTINCT mss from tcp_mss",
            "all.macaddress": "SELECT DISTINCT macAddress from ip_mac",
            "all.portnumber": "SELECT DISTINCT portNumber from ip_ports",
            "all.protocolname": "SELECT DISTINCT protocolName from ip_protocols"}

        # Retrieve values by selectors, if given, reduce results by extractor
        last_result = 0
        for q in query_param_list:
            # if selector, like avg, ttl, is given
            if any(e in q[0] for e in self._get_selector_keywords()):
                (keyword, param) = q
                query = named_queries.get(keyword + "." + param)
                self.cursor.execute(str(query))
                last_result = self.cursor.fetchall()
            # if selector is parametrized, i.e. ipAddress(mac=AA:BB:CC:DD:EE) or macAddress(ipAddress=192.168.178.1)
            elif any(e in q[0] for e in self._get_parametrized_selector_keywords()) and any(
                            o in q[1] for o in ["<", "=", ">", "<=", ">="]):
                (keyword, param) = q
                # convert string 'paramName1<operator1>paramValue1,paramName2<operator2>paramValue2,...' into list of triples
                param_op_val = [(key, op, value) for (key, op, value) in
                                [re.split("(<=|>=|>|<|=)", x) for x in param.split(",")]]
                last_result = self.named_query_parameterized(keyword, param_op_val)
            # if extractor, like random, first, last, is given
            elif any(e in q[0] for e in self._get_extractor_keywords()) and (
                        isinstance(last_result, list) or isinstance(last_result, tuple)):
                extractor = q[0]
                if extractor == 'random':
                    index = randint(a=0, b=len(last_result) - 1)
                    last_result = last_result[index]
                elif extractor == 'first':
                    last_result = last_result[0]
                elif extractor == 'last':
                    last_result = last_result[-1]

        return last_result

    def process_db_query(self, query_string_in: str, print_results=False, sql_query_parameters: tuple = None):
        """
        Processes a database query. This can either be a standard SQL query or a named query (predefined query).

        :param query_string_in: The string containing the query
        :param print_results: Indicated whether the results should be printed to terminal (True) or not (False)
        :param sql_query_parameters: Parameters for the SQL query (optional)
        :return: the results of the query
        """
        named_query_keywords = self.get_all_named_query_keywords()

        # Clean query_string
        query_string = query_string_in.lower().lstrip()

        # query_string is a user-defined SQL query
        result = None
        if sql_query_parameters is not None or query_string.startswith("select") or query_string.startswith("insert"):
            result = self._process_user_defined_query(query_string, sql_query_parameters)
        # query string is a named query -> parse it and pass it to statisticsDB
        elif any(k in query_string for k in named_query_keywords) and all(k in query_string for k in ['(', ')']):
            # Clean query_string
            query_string = query_string.replace(" ", "")

            # Validity check: Brackets
            brackets_open, brackets_closed = query_string.count("("), query_string.count(")")
            if not (brackets_open == brackets_closed):
                sys.stderr.write("Bracketing of given query '" + query_string + "' is incorrect.")

            # Parse query string into [ (query_keyword1, query_params1), ... ]
            delimiter_start, delimiter_end = "(", ")"
            kplist = []
            current_word = ""
            for char in query_string:  # process characters one-by-one
                # if char is no delimiter, add char to current_word
                if char != delimiter_end and char != delimiter_start:
                    current_word += char
                # if a start delimiter was found and the current_word so far is a keyword, add it to kplist
                elif char == delimiter_start:
                    if current_word in named_query_keywords:
                        kplist.append((current_word,))
                        current_word = ""
                    else:
                        print("ERROR: Unrecognized keyword '" + current_word + "' found. Ignoring query.")
                        return
                # else if characeter is end delimiter and there were no two directly following ending delimiters,
                # the current_word must be the parameters of an earlier given keyword
                elif char == delimiter_end and len(current_word) > 0:
                    kplist[-1] += (current_word,)
                    current_word = ""
            result = self._process_named_query(kplist[::-1])
        else:
            sys.stderr.write(
                "Query invalid. Only named queries and SQL SELECT/INSERT allowed. Please check the query's syntax!\n")
            return

        # If result is tuple/list with single element, extract value from list
        requires_extraction = (isinstance(result, list) or isinstance(result, tuple)) and len(result) == 1 and \
                              (not isinstance(result[0], tuple) or len(result[0]) == 1)

        while requires_extraction:
            if isinstance(result, list) or isinstance(result, tuple):
                result = result[0]
            else:
                requires_extraction = False

        # If tuple of tuples or list of tuples, each consisting of single element is returned,
        # then convert it into list of values, because the returned colum is clearly specified by the given query
        if (isinstance(result, tuple) or isinstance(result, list)) and all(len(val) == 1 for val in result):
            result = [c for c in result for c in c]

        # Print results if option print_results is True
        if print_results:
            if len(result) == 1 and isinstance(result, list):
                result = result[0]
                print("Query returned 1 record:\n")
                for i in range(0, len(result)):
                    print(str(self.cursor.description[i][0]) + ": " + str(result[i]))
            else:
                self._print_query_results(query_string_in, result)

        return result

    def _print_query_results(self, query_string_in: str, result):
        """
        Prints the results of a query.
        Based on http://stackoverflow.com/a/20383011/3017719.

        :param query_string_in: The query the results belong to
        :param result: The results of the query
        """
        # Print number of results according to type of result
        if isinstance(result, list):
            print("Query returned " + str(len(result)) + " records:\n")
        else:
            print("Query returned 1 record:\n")

        # Print query results
        if query_string_in.lstrip().upper().startswith(
                "SELECT") and result is not None and self.cursor.description is not None:
            widths = []
            columns = []
            tavnit = '|'
            separator = '+'
            for cd in self.cursor.description:
                widths.append(len(cd) + 10)
                columns.append(cd[0])
            for w in widths:
                tavnit += " %-" + "%ss |" % (w,)
                separator += '-' * w + '--+'
            print(separator)
            print(tavnit % tuple(columns))
            print(separator)
            if isinstance(result, list):
                for row in result:
                    print(tavnit % row)
            else:
                print(tavnit % result)
            print(separator)
        else:
            print(result)
