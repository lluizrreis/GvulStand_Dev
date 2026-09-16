from typing import List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app import models

def expand_descendant_group_ids(db: Session, group_ids: List[int]) -> List[int]:
    """
    Expande recursivamente uma lista de IDs de grupos de ativos para incluir
    todos os seus subgrupos descendentes em qualquer nível de profundidade hierárquica.
    Suporta múltiplos níveis (ex: Nível 1 Corporativo -> Nível 2 Subgrupo -> Nível 3 Área/Sistema).
    """
    if not group_ids:
        return []
    all_allowed = set(group_ids)
    current_parents = set(group_ids)
    while current_parents:
        child_ids = [
            cid for (cid,) in db.query(models.AssetGroup.id)
            .filter(models.AssetGroup.parent_id.in_(current_parents))
            .all()
        ]
        new_children = set(child_ids) - all_allowed
        if not new_children:
            break
        all_allowed.update(new_children)
        current_parents = new_children
    return list(all_allowed)

def get_descendant_group_ids(db: Session, asset_group_id: int, include_self: bool = True) -> List[int]:
    """
    Retorna a lista de IDs de todos os subgrupos descendentes do grupo informado em qualquer nível.
    """
    descendants = expand_descendant_group_ids(db, [asset_group_id])
    if not include_self:
        descendants = [gid for gid in descendants if gid != asset_group_id]
    return descendants

def is_descendant_of(db: Session, child_id: int, potential_ancestor_id: int) -> bool:
    """
    Verifica se child_id é descendente de potential_ancestor_id.
    Usado para prevenir referências circulares em qualquer nível de profundidade na árvore.
    """
    descendants = get_descendant_group_ids(db, potential_ancestor_id, include_self=False)
    return child_id in descendants

def compute_group_hierarchy_info(group: models.AssetGroup) -> Tuple[int, str]:
    """
    Calcula o nível hierárquico (1 = Corporativo, 2 = Subgrupo, 3 = Sub-subgrupo / Área, etc.)
    e o caminho estrutural completo (ex: 'Corporativo > TI Regional > Servidores Web').
    """
    level = 1
    path_names = [group.name]
    curr = group
    visited = {group.id}
    while curr.parent and curr.parent_id not in visited:
        level += 1
        curr = curr.parent
        visited.add(curr.id)
        path_names.insert(0, curr.name)
    return level, " > ".join(path_names)
