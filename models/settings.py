import cPickle as pickle
import logging

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
filename = 'nat_config.pkl'


def save(nat_dict):
    try:
        with open(filename, 'wb') as fp:
            pickle.dump(nat_dict, fp)
        return True
    except:
        logging.warning('Failed when saving pickled')
        return False


def load():
    try:
        with open(filename, 'rb') as fp:
            return pickle.load(fp)
    except:
        logging.warning('Failed when loading pickled')
        return None
