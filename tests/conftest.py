import pytest
import os

from dev_detect.storage import DatabaseStorage


@pytest.fixture(scope='function')
def storage(request, tmpdir):
    database_dir = tmpdir.mkdir('dev-detect')
    db_path = os.path.join(database_dir, 'dev-detect.db')
    storage = DatabaseStorage(db_path)

    if hasattr(request, 'param'):
        for item in request.param:
            print("Storing item {}".format(item))
            storage.store(item)

    yield storage
