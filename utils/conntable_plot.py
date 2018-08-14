# This program is to plot proc data exported by connection table
# This will be helpful to analyze connection stats from tests
# It generates two types of graphs
#   a) latency/connection from single test(wait + put + get)
#   b) compare latency/connection between two tests (wait/put/get)

import os
import Gnuplot
import ConfigParser

class GPlot(object):

    def __init__(self):
        self.g = Gnuplot.Gnuplot()
        self.rows = []
        self.filter_rows = []
        self.format_list = []
        self.file = None

    def load_data(self, fpath):
        head = True

        if os.path.exists(fpath) is False:
            raise Exception("data file %s not found" % fpath)

        with open(fpath, 'r') as f:
            for line in f:
                line = line.strip()
                line = line.split()
                if head:
                    self.format_list = line
                    head = False
                    continue
                self.rows.append(line)
        self.file = fpath

    def filter_data(self, key):
        for line in self.rows:
            if key in line:
                self.filter_rows.append(line)

    def create_plots(self, column_list):
        plots = []
        for i in column_list:
            y = []
            col = self.format_list.index(i)
            for row in self.filter_rows:
                y.append(int(row[col]))
            x = range(len(y))
            plots.append(Gnuplot.Data(x, y, title='{}-{}'.format(i, self.file),
                with_="linespoints"))
        return plots

    def merge_plots(self, plots, filename):
        self.g.title("conntable plot")
        self.g.xlabel("lane no")
        self.g.ylabel("latency (us)")
        self.g("set grid")
        #convert list to args
        self.g.plot(*plots)
        self.g.hardcopy(filename=filename, terminal='png')
        del self.g

    def reset_data(self):
        self.file = None
        self.rows = []
        self.filter_rows = []

#plotting recipes
def PlotConntable(filename, nodekey, field_list, output):
    G = GPlot()
    G.load_data(filename)
    G.filter_data(nodekey)
    p = G.create_plots(field_list)
    G.merge_plots(p, output)

def PlotConntableCompare(filename1, filename2, nodekey, field, output):
    G = GPlot()
    G.load_data(filename1)
    G.filter_data(nodekey)
    p1 = G.create_plots([field])

    G.reset_data()

    G.load_data(filename2)
    G.filter_data(nodekey)
    p2 = G.create_plots([field])
    G.merge_plots(p1 + p2, output)

#main function
def main():
    config = ConfigParser.ConfigParser()
    with open(r'conntable_plot.cfg') as f:
        config.readfp(f)
        sections = config.sections()
        if 'conntable-cfg' in sections:
            section = 'conntable-cfg'
            filename = config.get(section, 'procfile')
            node = config.get(section, 'node')
            col1 = config.get(section, 'column1')
            col2 = config.get(section, 'column2')
            col3 = config.get(section, 'column3')
	    path = config.get(section, 'output')
            PlotConntable(filename, node, [col1, col2, col3], path)

        if 'conntable-cfg-compare' in sections:
            section = 'conntable-cfg-compare'
            filename1 = config.get(section, 'procfile1')
            filename2 = config.get(section, 'procfile2')
            node = config.get(section, 'node')
            col = config.get(section, 'column')
	    path = config.get(section, 'output')
            PlotConntableCompare(filename1, filename2, node, col, path)

if __name__ == "__main__":
    main()
