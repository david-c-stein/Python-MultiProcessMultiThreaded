#!/usr/bin/env python


'''
    Package Description
        DeviceSurvey_Module

    CAUTION:
      EVERYTHING HERE IS REQUIRED TO BE THREAD SAFE !!!
'''


from device_manager import DeviceModule


class Module(DeviceModule):

    def __init__(self):
        super(Module, self).__init__()
        self.name = 'Survey Module'
        self.version = '0.1.0'
        self.description = 'This is an example module - performs a basic survey'

    def args(self, parser):
        #  Reserved types :  h, help   m, module
        return parser
    
    def using(self):
        return '''
                ./device_manager.py -m DeviceSurvey_Module -u <username> -p <password> -r <port> -d <device(s)>
               '''

    def pre_run(self):
        '''
          Those activities that need to be executed before connecting to devices
          ie) check for local dependencies ie) files, md5sums
        '''
        pass


    def run(self):
    
        # --------------------------
        # Log device version
        data = self.client.cmd('uname -a')
        self.info( str(data[0]) )

        try:
            pass
            # do thread safe stuffs here        
        
        except Exception as err:
            self.error("Excpetion : %s " % str(err))



