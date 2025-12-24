"""
PasswordHasher - Service pour le hachage des mots de passe
"""

from passlib.context import CryptContext


class PasswordHasher:
    """Service pour le hachage et la vérification des mots de passe"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def hash(self, password: str) -> str:
        """Génère un hachage pour un mot de passe"""
        return self.pwd_context.hash(password)
    
    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """Vérifie un mot de passe non haché contre un mot de passe haché"""
        return self.pwd_context.verify(plain_password, hashed_password)

