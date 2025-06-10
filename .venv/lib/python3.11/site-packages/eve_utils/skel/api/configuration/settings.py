import os

class Singleton:
    """
    A non-thread-safe helper class to ease implementing singletons.
    This should be used as a decorator -- not a metaclass -- to the
    class that should be a singleton.

    The decorated class can define one `__init__` function that
    takes only the `self` argument. Also, the decorated class cannot be
    inherited from. Other than that, there are no restrictions that apply
    to the decorated class.

    To get the singleton instance, use the `instance` method. Trying
    to use `__call__` will result in a `TypeError` being raised.

    """

    def __init__(self, decorated):
        self._decorated = decorated

    def instance(self):
        """
        Returns the singleton instance. Upon its first call, it creates a
        new instance of the decorated class and calls its `__init__` method.
        On all subsequent calls, the already created instance is returned.

        """
        try:
            return self._instance
        except AttributeError:
            self._instance = self._decorated()
            return self._instance

    def __call__(self):
        raise TypeError('Singletons must be accessed through `instance()`.')



@Singleton
class Settings():
    """
    A collection of grouped name/value pairs that act as setting/configuration items.
    Groups are identified by a prefix.
    
    This class is a singleton and can only be used via its instance() method.
    
    These name/value pairs must first be created.  They can be set in three ways:
    - through this class's methods
    - overridden by environment variables
    - overridden by the contents of an optional file named `_env.conf`
        Each line in the _env.conf is in the format "name=value".  
        Blank/whitespace lines and lines staring with # are ignored.
    
    Methods:
      create                  Adds a group and a name to the collection, with an 
                              optional default_value.  Set `is_optional` to True 
                              and this setting will not be visible when its value 
                              is None
                  
      set_prefix_description  Provide a textual description for a prefix which will
                              be displayed when dumping
                              
      get                     Used to look up the value of a setting.  If the setting name
                              you want to look up has the prefix in it, leave `prefix` None
                              and the method will parse
                              e.g. 
                                  prefix == None, setting_name == ES_INSTANCE_NAME 
                                     becomes 
                                  prefix == ES, setting_name == INSTANCE_NAME
                                  
      is_enabled              A value is considered "enabled" if it begins with Y, T, or E          
                              i.e. the following means a setting (if it exists) is enabled:
                              - 'Yes' or 'yes' or 'Y' or 'y'
                              - 'True' or 'true' or 'T' or 't'
                              - 'Enabled' or 'enabled' or 'E' or 'e'
  
      dump                    output all settings by group/prefix.
                              If you do not supply a callback, the method will use print()
                              This gives you the ability to pass callback=LOG.info to 
                              redirect the dump output to your logger
                              
      []                      You can use square brackets to access (and change) settings
                              whose name has the begins with the prefix
                              e.g.
                                  port = settings['ES_API_PORT']
                                  settings['ES_LOGGING_LEVEL'] = 'Debug'
    """
    def __init__(self):
        self.settings = {}
        self.optional_settings = {}
        self.prefix_descriptions = {}

    # __OVERLOADS__
    def __getitem__(self, setting_name):
        return self.get(setting_name)

    def __setitem__(self, setting_name, value):
        prefix, setting_name = self._parse_setting_name(setting_name)
        if prefix in self.settings and setting_name in self.settings[prefix]:
            self.settings[prefix][setting_name] = value
        else:
            raise ValueError(f'{prefix}_{setting_name} does not exist - create it first before assigning a value')

    def __contains__(self, setting_name):
        prefix, setting_name = self._parse_setting_name(setting_name)
        return prefix in self.settings and setting_name in self.settings[prefix]

    # PUBLIC METHODS
    def create(self, prefix, setting_name, default_value=None, is_optional=False):
        prefix = prefix.upper()
        if prefix not in self.settings:
            self.settings[prefix] = {}
        if is_optional and prefix not in self.optional_settings:
            self.optional_settings[prefix] = {}
        
        if type(setting_name) is dict:  # is_optional is ignored
            settings = setting_name
            for setting_name in settings:
                if setting_name.upper() in self.settings[prefix]:
                    raise ValueError(f'settings[{prefix}][{setting_name.upper()}] already exists')
                self.settings[prefix][setting_name.upper()] = settings[setting_name]
        else:
            setting_name = setting_name.upper()            
            if setting_name in self.settings[prefix]:
                raise ValueError(f'settings[{prefix}][{setting_name}] already exists')
            if is_optional:
                self.optional_settings[prefix][setting_name] = default_value
            else:
                self.settings[prefix][setting_name] = default_value

    def set_prefix_description(self, prefix, description):
        prefix = prefix.upper()
        if prefix not in self.settings:
            self.settings[prefix] = {}
        if prefix not in self.prefix_descriptions:
            self.prefix_descriptions[prefix] = ''
        self.prefix_descriptions[prefix] = description

    def get(self, setting_name, prefix=None, default_value=None):
        self._set_from_environment()
        setting_name = setting_name.upper()
        if not prefix:
            prefix, setting_name = self._parse_setting_name(setting_name)

        return self.settings.get(prefix, {}).get(setting_name, default_value)

    def dump(self, prefix=None, callback=None):
        self._set_from_environment()
        if not callback:
            callback = print

        if prefix:
            self._dump_prefix(prefix, callback)
        else:
            for prefix in self.settings:
                self._dump_prefix(prefix, callback)
                
    def is_enabled(self, setting_name, prefix=None):
        value = self.get(setting_name, prefix)
        
        return value[0].upper() in 'YTE' if value else False
            # i.e. the following means a setting (if it exists) is enabled:
            # - 'Yes' or 'yes' or 'Y' or 'y'
            # - 'True' or 'true' or 'T' or 't'
            # - 'Enabled' or 'enabled' or 'E' or 'e'

    # _PRIVATE METHODS
    def _set_from_environment(self):
        if os.path.exists('_env.conf'):
            with open('_env.conf') as setting:
                for line in setting:
                    if not line.startswith('#'):
                        line = line.rstrip()
                        nvp = line.split('=')
                        if len(nvp) == 2:
                            os.environ[nvp[0].strip()] = nvp[1].strip()

        for prefix in self.settings:
            for setting_name in self.settings[prefix]:
                old_value = self.settings[prefix][setting_name]  # TODO: refactor with optional below
                new_value = os.environ.get(f'{prefix}_{setting_name}', self.settings[prefix][setting_name])
                if old_value and not isinstance(old_value, str):
                    try:
                        new_value = type(old_value)(new_value)
                    except ValueError:
                        raise TypeError(f'attempt to set {prefix}_{setting_name} to a different type than its default value (should be {type(old_value)}).')
                self.settings[prefix][setting_name] = new_value
                
        for prefix in self.optional_settings:
            for setting_name in self.optional_settings[prefix]:
                old_value = self.optional_settings[prefix][setting_name]  # TODO: refactor with non-optional above
                new_value = os.environ.get(f'{prefix}_{setting_name}')
                if new_value:
                    if not isinstance(old_value, str) and not isinstance(old_value, type(None)):
                        try:
                            new_value = type(old_value)(new_value)
                        except ValueError:
                            raise TypeError(f'attempt to set {prefix}_{setting_name} to a different type than its default value (should be {type(old_value)}).')

                    if new_value:
                        self.settings[prefix][setting_name] = new_value

    def _parse_setting_name(self, setting_name):
        first_underscore = setting_name.index('_')
        prefix = setting_name[:first_underscore]
        setting_name = setting_name[first_underscore+1:]
        return prefix, setting_name

    def _dump_prefix(self, prefix, callback):
        if prefix in self.prefix_descriptions:
            callback(f"== {prefix}: {self.prefix_descriptions[prefix]}")
        for setting_name in sorted(self.settings[prefix]):
            value = self.settings[prefix][setting_name]
            if ('PASSWORD' in setting_name) or ('SECRET' in setting_name):
                value = '***'
            callback(f'{prefix}_{setting_name}: {value}')



# TODO: handle cancellable values
if __name__ == '__main__':
    settings = Settings.instance()
    settings.set_prefix_description('es', 'EveService base settings')
    settings.create('es', 'api_name', 'ishowroom-catalog-api')
    settings.create('es', {
        'INSTANCE_NAME': 'my service name',
        'TRACE_LOGGING': 'Enabled',
        'ADD_ECHO': 'False',
        'API_PORT': 2112
    })

    auth_settings = Settings.instance()
    auth_settings.set_prefix_description('es-auth', 'EveService authorization settings')
    auth_settings.create('es-auth', 'enable_Basic', 'Yes')
    auth_settings.create('es-auth', 'root_password', 'swordfish')

    settings.dump()
    print('==========\n')

    print(f"settings['ES_INSTANCE_NAME']: {settings['ES_INSTANCE_NAME']}")
    print('...changing instance name')
    settings['ES_INSTANCE_NAME'] = 'new name via __setitem__'
    print(f"settings['ES_INSTANCE_NAME']: {settings['ES_INSTANCE_NAME']}")
    
    print('==========\n')
    
    print(f'ES_API_PORT in settings: {"ES_API_PORT" in settings}')
    print(f'ES_NOT_CREATED in settings {"ES_NOT_CREATED" in settings}')

    print('==========\n')
    
    print(f'is ES_TRACE_LOGGING enabled? {settings.is_enabled("ES_TRACE_LOGGING")}')
    print(f'is ES_ADD_ECHO enabled? {settings.is_enabled("ES_ADD_ECHO")}')
    print(f'IS ES_NOT_CREATED enabled {settings.is_enabled("ES_NOT_CREATED")}')

    print('==========\n')

    
