import pytest
import os

from dev_detect.storage import Storage


@pytest.fixture
def database_dir(tmpdir):
    return tmpdir.mkdir('dev-detect')


@pytest.fixture
def db_path(database_dir):
    return os.path.join(database_dir, 'dev-detect.db')


@pytest.fixture
def storage(db_path):
    yield Storage(db_path)
