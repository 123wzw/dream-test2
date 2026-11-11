"""测试隔离保障。

两个测试模块都在 import 阶段改写 AUTHKIT_DB，而 app.main 只在首次导入时
初始化数据库，导入顺序不同会导致某个模块指向的库未建表。
这里在每个用例执行前按当前环境变量幂等初始化一次，消除导入顺序依赖。
"""

import pytest

from app import store


@pytest.fixture(autouse=True)
def _ensure_database_initialized():
    store.init_db()
    yield
