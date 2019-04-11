from mock import patch
import pytest

from blazeutils.strings import randchars
from keg_auth.grids import (
    ActionColumn,
    make_user_grid,
    make_group_grid,
    make_bundle_grid,
)
from webgrid import BaseGrid


class TestActionColumnLinkClasses(object):
    @pytest.mark.parametrize('grid_fun', [
        make_user_grid,
        make_group_grid,
        make_bundle_grid,
    ])
    def test_link_classes(self, grid_fun):
        class MyActionColumn(ActionColumn):
            default_view_link_class = randchars(20)
            default_edit_link_class = randchars(20)
            default_delete_link_class = randchars(20)

        class Grid(BaseGrid):
            action_column_cls = MyActionColumn

        view_class = MyActionColumn.default_view_link_class
        edit_class = MyActionColumn.default_edit_link_class
        delete_class = MyActionColumn.default_delete_link_class

        with patch.object(Grid, 'action_column_cls') as m_ac_init:
            grid_fun('edit_endpoint', None, 'delete_endpoint', None, grid_cls=Grid)
            m_ac_init.assert_called_once()

        grid = grid_fun('edit_endpoint', None, 'delete_endpoint', None, grid_cls=Grid)
        assert grid.action_column_cls == MyActionColumn

        for col in [col for col in grid.__cls_cols__ if isinstance(col, ActionColumn)]:
            assert isinstance(col, MyActionColumn)
            assert col.view_link_class_for(None) == view_class
            assert col.edit_link_class_for(None) == edit_class
            assert col.delete_link_class_for(None) == delete_class
            col.view_endpoint = 'view_endpoint'
            patch_extract_data = patch('keg_auth.grids.ActionColumn.extract_data')
            patch_grid = patch.object(col, 'grid')
            patch_url_for = patch('flask.url_for', return_value='/url')
            with patch_extract_data, patch_grid, patch_url_for:
                result = col.extract_and_format_data(None)
                for cls in [view_class, edit_class, delete_class]:
                    assert cls in result
