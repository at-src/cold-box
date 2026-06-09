"""Accept sparse PAE page tables that stock Vol3 rejects (Win2008-era dumps)."""
from __future__ import annotations

import logging
import os
from typing import Optional

from volatility3.framework import constants, interfaces
from volatility3.framework.automagic.windows import DtbSelfRefPae, PageMapScanner
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)


class SparsePaeDtbStacker(interfaces.automagic.StackerLayerInterface):
    """Stack Windows PAE when DTB self-ref exists but page table has <10 entries."""

    stack_order = 41
    exclusion_list = ["mac", "linux"]

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        base_layer = context.layers[layer_name]
        if isinstance(base_layer, intel.Intel):
            return None
        if base_layer.metadata.get("os") not in (None, "Windows", "Unknown"):
            return None

        forced = os.environ.get("VOL_FORCE_DTB", "").strip()
        if forced:
            page_map_offset = int(forced, 0)
        else:
            hits = list(
                base_layer.scan(
                    context,
                    PageMapScanner(tests=[DtbSelfRefPae()]),
                    progress_callback=progress_callback,
                )
            )
            if not hits:
                return None
            page_map_offset = hits[0][1]

        test = DtbSelfRefPae()
        new_layer_name = context.layers.free_layer_name("IntelLayer")
        config_path = interfaces.configuration.path_join("IntelHelper", new_layer_name)
        context.config[
            interfaces.configuration.path_join(config_path, "memory_layer")
        ] = layer_name
        context.config[
            interfaces.configuration.path_join(config_path, "page_map_offset")
        ] = page_map_offset

        vollog.info("SparsePaeDtbStacker using DTB %s", hex(page_map_offset))
        return test.layer_type(
            context,
            config_path=config_path,
            name=new_layer_name,
            metadata={"os": "Windows"},
        )
