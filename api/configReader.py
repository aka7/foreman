import csv
import operator

# fucntions to read and write keyvalue entries

def read_properties(filename):
    """ Reads a given properties file with each line of the format key=value.  Returns a dictionary containing the pairs.

    Keyword arguments:
        filename -- the name of the file to be read
    """
    result={ }
    with open(filename, "rb") as csvfile:
        reader = csv.reader(csvfile, delimiter='=', escapechar='\\', quoting=csv.QUOTE_NONE)
        for row in reader:
            if len(row) != 2:
                raise csv.Error("Too many fields on row with contents: "+str(row))
            result[row[0]] = row[1] 
    return result

def write_properties(filename,dictionary):
    """ Writes the provided dictionary in key-sorted order to a properties file with each line of the format key=value

    Keyword arguments:
        filename -- the name of the file to be written
        dictionary -- a dictionary containing the key/value pairs.
    """
    with open(filename, "wb") as csvfile:
        writer = csv.writer(csvfile, delimiter='=', escapechar='\\', quoting=csv.QUOTE_NONE)
        for key, value in sorted(dictionary.items(), key=operator.itemgetter(0)):
                writer.writerow([ key, value])
