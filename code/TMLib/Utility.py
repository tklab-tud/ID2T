import json
import yaml

import os


###############################################
################## Parsing
###############################################


def parse_yaml_args_withReference(config_filepath, arg_filepath):
    """
    Parses input arg(ument) yml file and default config file. Creates resulting
    dictionary of arguments and their values. 
    Arguments in arg file that are not in config file are ignored.
    Arguments in config file and not in arg file are assigned default value from config file.

    Arguments must by listed in dictionary form.

    :param config_filepath: yml file containing default values for all accepted arguments
    :param arg_filepath: yml file containing input arguments and their values
    :return: dictionary of argument (based on config) and their values (based on arg file and config)
    """
    with open(config_filepath, 'r') as stream:
        try:
            config = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc) # add logger

    with open(arg_filepath, 'r') as stream:
        try:
            args = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc) # add logger

    for key in config.keys():
        if  key in args:
            config[key] = args[key]

    return config


def parse_yaml_args(config_filepath):
    """
    Parses input config into a dictionary. 

    :param config_filepath: YAML file path
    :return: dinctionary of arguments and values
    """
    if not config_filepath:
        raise TypeError("NoneType passed as a path to yaml config file.")

    if not os.path.isfile(config_filepath):
        raise ValueError("File " + config_filepath + "does not exist")

    with open(config_filepath, 'r') as stream:
        try:
            config = yaml.load(stream)
        except yaml.YAMLError as exc:
            print("Error occured while parsing yaml config.")
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                print("Error position: (%s:%s)" % (mark.line+1, mark.column+1))
            raise ValueError("Invalid config.") from exc

    return config


def parse_json_args(config_filepath):
    """
    Parses input config into a dictionary. 

    :param config_filepath: json file path
    :return: dinctionary of arguments and values
    """
    if not config_filepath:
        raise TypeError("NoneType passed as a path to json config file.")

    if not os.path.isfile(config_filepath):
        raise ValueError("File " + config_filepath + "does not exist")

    with open(config_filepath, 'r') as stream:
        try:
            config = json.load(stream)
        except json.JSONDecodeError as exc:
            print("Error occured while parsing json config.")
            if hasattr(exc, 'lineno') and hasattr(exc, 'colno'):
                print("Error position: (%s:%s)" % (exc.lineno, exc.colno))
            raise ValueError("Invalid config.") from exc
    return config


###############################################
################## Generic functions
###############################################


def donothing(*args):
    """
    Just like a student until week before deadline, it does nothing regardless of what you throw at it
    """
    pass

