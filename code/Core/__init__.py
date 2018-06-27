# Set the required backend as early as possible to avoid conflicts
import matplotlib as mplt
mplt.use('Cairo', force=True)
