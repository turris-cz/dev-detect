import pytest
import os

from dev_detect.storage import Storage


@pytest.fixture(scope='function')
def storage(request, tmpdir):
    database_dir = tmpdir.mkdir('dev-detect')
    db_path = os.path.join(database_dir, 'dev-detect.db')
    mystorage = Storage(db_path)

    if hasattr(request, 'param'):
        for item in request.param:
            print("Storing item {}".format(item))
            mystorage.store(item)

    yield mystorage
