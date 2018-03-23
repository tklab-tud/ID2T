import random, copy

# information taken from https://www.cymru.com/jtk/misc/ephemeralports.html
class PortRanges:
	# dynamic ports as listed by RFC 6056
	DYNAMIC_PORTS = range(49152, 65536)
	
	LINUX = range(32768, 61001)
	FREEBSD = range(10000, 65536)
	
	APPLE_IOS = DYNAMIC_PORTS
	APPLE_OSX = DYNAMIC_PORTS
	
	WINDOWS_7 = DYNAMIC_PORTS
	WINDOWS_8 = DYNAMIC_PORTS
	WINDOWS_VISTA = DYNAMIC_PORTS
	WINDOWS_XP = range(1024, 5001)

# This class uses classes instead of functions so deepcloning works
class PortSelectionStrategy:
	class sequential:
		def __init__(self):
			self.counter = -1
		
		# that function will always return a one higher counter than before,
		# restarting from the start once it reached the highest value
		def __call__(self, port_range, *args):
			if self.counter == -1:
				self.counter = port_range.start
			
			port = self.counter
			
			self.counter += 1
			if self.counter == port_range.stop:
				self.counter = port_range.start
			
			return port
	class random:
		def __call__(self, port_range, *args):
			return random.randrange(port_range.start, port_range.stop)

	class linux_kernel:
		"""
		A port-selectioin-strategy oriented on the linux-kernel
		The implementation follows https://github.com/torvalds/linux/blob/master/net/ipv4/inet_connection_sock.c#L173
		as much as possible when converting from one language to another (The newest file was used
		by the time of writing, make sure you select the correct one when following the link!)
		"""

		def __call__(self, port_range: range, port_selector, *args):
			"""
			This method is an attempt to map a c-function to python. To solve the goto-problem
			while-true's have been added. Both of the while-true's are placed where the original
			had a label to jump to. break's and continue's are set to preserve the original
			control flow. Another method could have been used to rewrite the c-code, however this
			was chosen to preserve the similarity between this and the original

			:param port_range: the port range to choose from
			:param port_selector: the port selector that tells which ports are in use
			:param args: Not used for now
			:return: A port number
			"""
			port = 0
			low, high = port_range.start, port_range.stop

			# this var tells us if we should use the upper or lower port-range-half, or the whole range if
			# this var is None. The original was an enum of the values 0, 1 and 2. But I think an Optional[bool]
			# is more clear
			# None: use whole range, True: use lower half, False: use upper half
			attempt_half = True

			high += 1  # line 186 in the original file
			while True:
				if high - low < 4:
					attempt_half = None
				if attempt_half is not None:
					# appearently a fast method to find a number close to the real half
					# unless the difference between high and low is 4 (see above, note the 2-shift below)
					# this does not work
					half = low + (((high - low) >> 2) << 1)

					if attempt_half:
						high = half
					else:
						low = half

				remaining = high - low
				if remaining > 1:
					remaining &= ~1 # flip the 1-bit

				offset = random.randrange(0, remaining)
				offset |= 1;

				attempt_half_before = attempt_half # slight hack to keep track of change
				while True:
					port = low + offset

					for i in range(0, remaining, 2):
						if port >= high:
							port -= remaining

						if port_selector.is_port_in_use(port):
							port += 2
							continue

						return port

					offset -= 1
					if not (offset & 1):
						continue

					if attempt_half:
						attempt_half = False
						break

				if attempt_half_before: # we still got ports to search, attemp_half was just set to False
					continue
				if not attempt_half: # the port-range is exhausted
					break

			raise ValueError("Could not find suitable port")

class PortSelector:
	"""
	This class simulates a port-selection-process. Instances keep a list of port-numbers they generated so
	the same port-number will not be generated again.
	"""
	
	def __init__(self, port_range, select_function):
		"""
		Create a PortSelector given a range of ports to choose from and a function that chooses the next port
		
		:param port_range: a range-object containing the range of ports to choose from
		:param select_function: a function that receives the port_range and selects a port
		"""
		
		if len(port_range) == 0:
			raise ValueError("cannot choose from an empty range")
		if port_range.start not in range(1, 65536) or port_range.stop not in range(1, 65536 + 1):
			raise ValueError("port_range is no subset of the valid port-range")
		
		self.port_range = port_range
		
		self._select_port = select_function
		
		self.generated = []
	
	def select_port(self):
		# do this check to avoid endless loops
		if len(self.generated) == len(self.port_range):
			raise RuntimeError("All %i port numbers were already generated, no more can be generated" % len(self.port_range))
		
		while True:
			port = self._select_port(self.port_range, self)
			
			if port not in self.generated:
				self.generated.append(port)
				return port
	
	def is_port_in_use(self, port: int):
		return port in self.generated
	
	def undo_port_use(self, port: int):
		if port in self.generated:
			self.generated.remove(port)
		else:
			raise ValueError("Port %i is not in use and thus can not be undone" % port)
	
	def reduce_size(self, size: int):
		"""
		Reduce the list of already generated ports to the last <size> generated.
		If size if bigger than the number of generated ports nothing happens.
		"""
		self.generated = self.generated[-size:]
	
	def clear(self):
		"""
		Clear the list of generated ports. As of now this does not reset the state of the selection-function
		"""
		self.generated = []
	
	def clone(self):
		return copy.deepcopy(self)

class ProtocolPortSelector:
	"""
	This class contains a method to select ports for udp and tcp. It generally consists of the port-selectors, one
	for tcp and one for udp. For convenience this class has a __getattr__-method to call methods on both selectors
	at once. E.g, clear() does not exist for ProtocolPortSelector but it does for PortSelector, therefore
	protocolPortSelector.clear() will call clear for both port-selectors.
	"""
	
	def __init__(self, port_range, select_tcp, select_udp = None):
		self.tcp = PortSelector(port_range, select_tcp)
		self.udp = PortSelector(port_range, select_udp or select_tcp)
	
	def get_tcp_generator(self):
		return self.tcp
	
	def get_udp_generator(self):
		return self.udp
	
	def select_port_tcp(self):
		return self.tcp.select_port()
	
	def select_port_udp(self):
		return self.udp.select_port()
	
	def is_port_in_use_tcp(self, port):
		return self.tcp.is_port_in_use(port)
	
	def is_port_in_use_udp(self, port):
		return self.udp.is_port_in_use(port)
	
	def clone(self):
		class Tmp: pass
		clone = Tmp()
		clone.__class__ = type(self)
		
		clone.udp = self.udp.clone()
		clone.tcp = self.tcp.clone()
		
		return clone
	
	def __getattr__(self, attr):
		val = getattr(self.tcp, attr)
		
		if callable(val): # we proprably got a method here
			tcp_meth = val
			udp_meth = getattr(self.udp, attr)
			
			def double_method(*args, **kwargs):
				return (tcp_meth(*args, **kwargs), udp_meth(*args, **kwargs))
			
			return double_method # calling this function will call the method for both port-selectors
		else: # we have found a simple value, return a tuple containing the attribute-value from both port-selectors
			return (val, getattr(self.udp, attr))

class PortSelectors:
	"""
	To save some time this class contains some of the port-selection-strategies found in the wild. It is recommend to use
	.clone() to get your personal copy, otherwise two parts of your code might select ports on the same port-selector which
	is something your might want to avoid.
	"""
	LINUX = ProtocolPortSelector(PortRanges.LINUX, PortSelectionStrategy.random())
	APPLE = ProtocolPortSelector(PortRanges.DYNAMIC_PORTS,
			PortSelectionStrategy.sequential(),
			PortSelectionStrategy.random())
	FREEBSD = ProtocolPortSelector(PortRanges.FREEBSD, PortSelectionStrategy.random())
	WINDOWS = ProtocolPortSelector(PortRanges.WINDOWS_7, PortSelectionStrategy.random()) # the selection strategy is a guess as i can't find more info on it

