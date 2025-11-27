"""Tests unitaires pour ProjectService."""

from typing import List, Optional

from domain.entities.project import Project
from domain.repositories.project_repository import ProjectRepository
from application.services.project_service import ProjectService


class InMemoryProjectRepository(ProjectRepository):
    """Implémentation en mémoire de ProjectRepository pour les tests."""

    def __init__(self) -> None:
        self._projects: List[Project] = []

    def find_by_id(self, project_id: str) -> Optional[Project]:
        return next((p for p in self._projects if p.id == project_id), None)

    def find_by_name(self, name: str) -> Optional[Project]:
        return next((p for p in self._projects if p.name == name), None)

    def find_by_api_key(self, api_key: str) -> Optional[Project]:
        return next((p for p in self._projects if p.api_key == api_key), None)

    def find_all(self) -> List[Project]:
        return list(self._projects)

    def save(self, project: Project) -> Project:
        existing = self.find_by_id(project.id)
        if existing:
            self._projects = [
                project if p.id == project.id else p for p in self._projects
            ]
        else:
            self._projects.append(project)
        return project

    def delete(self, project_id: str) -> None:
        self._projects = [p for p in self._projects if p.id != project_id]

    def find_by_user_id(self, user_id: str) -> List[Project]:
        # Pour l’instant, on ne gère pas les liens user<->project dans ce repo en mémoire.
        return []

    def assign_to_user(self, project_id: str, user_id: str) -> None:
        # Méthode requise par l’interface, pas utile pour ces tests.
        return None

    def remove_from_user(self, project_id: str, user_id: str) -> None:
        # Méthode requise par l’interface, pas utile pour ces tests.
        return None


def test_create_project_success():
    repo = InMemoryProjectRepository()
    service = ProjectService(repo)

    project = service.create_project("My Project")

    assert project.name == "My Project"
    assert project.api_key.startswith("vk_")
    # 2 caractères "vk" + "_" + 32 caractères alphanumériques
    assert len(project.api_key) == 35
    # Le projet est bien stocké dans le repository
    assert repo.find_by_id(project.id) is not None


def test_create_project_duplicate_raises_value_error():
    repo = InMemoryProjectRepository()
    service = ProjectService(repo)

    # Premier projet OK
    service.create_project("Existing")

    # Deuxième avec le même nom -> erreur
    try:
        service.create_project("Existing")
        assert False, "create_project aurait dû lever ValueError pour projet existant"
    except ValueError as exc:
        assert "already exists" in str(exc)


def test_verify_api_key_ok_and_ko():
    repo = InMemoryProjectRepository()
    service = ProjectService(repo)

    project = service.create_project("SecureProject")

    # Clé correcte
    verified = service.verify_api_key(project_name="SecureProject", api_key=project.api_key)
    assert verified.id == project.id

    # Projet inexistant
    try:
        service.verify_api_key("Unknown", "whatever")
        assert False, "verify_api_key aurait dû lever ValueError pour projet inconnu"
    except ValueError as exc:
        assert "not found" in str(exc)

    # Mauvaise clé
    try:
        service.verify_api_key("SecureProject", "vk_invalid_key")
        assert False, "verify_api_key aurait dû lever ValueError pour clé invalide"
    except ValueError as exc:
        assert "Invalid API key" in str(exc)


