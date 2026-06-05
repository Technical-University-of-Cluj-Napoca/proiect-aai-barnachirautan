import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.dtos import FeedbackDTO
import chromadb
from langchain_openai import OpenAIEmbeddings
from dotenv import load_dotenv

class SelfImprovingFeedbackAgent:

    def __init__(self):
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        self.client = chromadb.PersistentClient(path="memory/feedback_index/")
        existing = [c.name for c in self.client.list_collections()]
        if "episodic_memory" in existing:
            col = self.client.get_collection("episodic_memory")
            meta = col.metadata or {}  # daca metadata e None, foloseste {}, cosine ne interesaza , e distanta
            if meta.get("hnsw:space") != "cosine":
                self.client.delete_collection("episodic_memory")
                self.memory_collection = self.client.create_collection(
                    "episodic_memory",
                    metadata={"hnsw:space": "cosine"}
                )
            else:
                self.memory_collection = col
        else:
            self.memory_collection = self.client.create_collection(
                "episodic_memory",
                metadata={"hnsw:space": "cosine"}
            )
        self.memory_threshold = 0.75

    # PRIMESC DIN UI UN FALSE POSITIVE, ADICA UN FEEDBACKDTO
    def store_feedback(self, dto: FeedbackDTO, path : str = 'memory/feedback_store.json'):
        #salvez feedback cu ce a gresit pt a stii in viitor sa se verifice de aici
        with open(path, "r", encoding="utf-8") as f:
            existing = json.load(f)
        existing.append(dto.model_dump()) # ca sa fie json

        with open(path, "w", encoding='utf-8') as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)

        text = (f"[{'FP' if dto.is_false_positive else 'TP'}] {dto.agent_verdict} in {dto.file_path}: "
                f"{dto.human_comment}. Cod: {dto.code_snippet[:200]}")


        vector = self.embeddings.embed_query(text)
        self.memory_collection.add(
            ids=[dto.feedback_id],
            embeddings=[vector],
            documents=[text],
            metadatas=[{
                "is_false_positive": dto.is_false_positive,
                "original_finding_id": dto.original_finding_id,
                "file_path": dto.file_path
            }]
        )

    #caut similaritate dupa cod
    def augment_context(self, code:str) -> str:
        vector = self.embeddings.embed_query(code)
        docs = self.memory_collection.query(
            query_embeddings=[vector],
            n_results=3
        )
        notes = []
        for text, dist in zip(docs["documents"][0], docs["distances"][0]): # iau din vector documentele,text si distantele pt scor
            score = 1 - dist
            if score >= self.memory_threshold:
                notes.append(f"Nota din review-urile anterioare: {text}")
        if not notes:
            return ""

        return "\n".join(notes)

    def reset_memory(self):
        with open("memory/feedback_store.json", "w", encoding="utf-8") as f:
            json.dump([], f)
        self.client.delete_collection("episodic_memory")  # sterg si recreez memoria
        self.memory_collection = self.client.create_collection(  # recreez
            "episodic_memory",
            metadata={"hnsw:space": "cosine"}
        )

