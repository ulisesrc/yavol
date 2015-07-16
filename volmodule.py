import volatility.obj as obj
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.filescan as filescan
import volatility.plugins.taskmods as taskmods
import volatility.plugins.connections as connections
import volatility.plugins.connscan as connscan
import volatility.plugins.sockets as sockets
import volatility.plugins.sockscan as sockscan
import volatility.plugins.netscan as netscan
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.imageinfo as imageinfo

from cStringIO import StringIO


import pprint

import yara


def logger(func):
    def forward(*args, **kwargs):
        print "Arguments were: %s, %s" % (args, kwargs)
        return func(*args, **kwargs)
    return forward

class retObj():
    def __init__(self, status, textVal):
        self.status = status
        self.textVal = textVal # used for imageinfo & yarascan


class VolatilityFunctions():

    def __init__(self, fname, profile, yara_rules_path, output_path):
        self.config = conf.ConfObject()
        self.path = fname
        self.profile = profile
        registry.PluginImporter()
        registry.register_global_options(self.config, commands.Command)
        registry.register_global_options(self.config, addrspace.BaseAddressSpace)
        self.config.parse_options(False)

        profs = registry.get_plugin_classes(obj.Profile)

        if self.profile != "imageinfo":
            self.config.PROFILE = self.profile
        #else:
        #    raise ValueError, "Wrong image type (imageinfo)"
        #self.config.LOCATION = "file:///" + self.path
        self.config.LOCATION = 'file://' + self.path
        #self.config.OUTPUT_FILE = args.file + '.sqlite'

        self.config.OUTPUT = 'sqlite'
        self.config.OUTPUT_FILE = output_path
        #self.config.output_file = "file:///home/yary/git/yavol_qt/yavol.sqlite"
        #self.config.YARA_FILE = config.yara_sigs
        self.config.parse_options(False)
        self.config.YARA_FILE = yara_rules_path

        #profile = profs[self.config.PROFILE]()



    def imageinfo(self):
        info = imageinfo.ImageInfo(self.config)
        info_table = StringIO()
        info_data = info.calculate()
        info.render_text(info_table, info_data)
        info_list = info_table.getvalue()
        return info_list

    '''
    def dlllist(self):
        self.config.NAME = 'explore'

        dll = taskmods.DllList(self.config)
        dlltable = StringIO()
        dlldata = dll.calculate()
        dll.render_text(dlltable, dlldata)
        dlllist = dlltable.getvalue()

        # clean config
        self.config.NAME = None

        return dlllist
    '''

    def mlwr_yarascan(self):
        #self.config.YARA_FILE = '/home/yary/git/yavol_qt/yara_rules/ye_memory.yar'
        mlwr = malfind.YaraScan(self.config)
        mlwr_table = StringIO()
        mlwr_data = mlwr.calculate()
        mlwr.render_text(mlwr_table, mlwr_data)
        mlwr_yarascan = mlwr_table.getvalue()
        return mlwr_yarascan


    @logger
    def runModule(self, name):
        print self.profile

        if self.profile == 'imageinfo':
            retValtxt = self.imageinfo()

            return retObj(True, retValtxt)

        #elif name == 'yarascan':

        #    retValtxt = self.mlwr_yarascan()

        #    if not retValtxt: # when there is no hit, we will have an empty string here
        #        retValtxt = 'No hits!'

        #    return retObj(True, retValtxt)

        else:
            cmds = registry.get_plugin_classes(commands.Command, lower = True)
            command = cmds[name](self.config)

            try:
                calc = command.calculate()
                command.render_sqlite(self.config.OUTPUT_FILE, calc)
                #self.finished.emit()
                return retObj(True, None)

            except Exception as err:
                print err.message
                return retObj(None, None)
