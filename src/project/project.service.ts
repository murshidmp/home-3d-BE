// src/project/project.service.ts
import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Project } from './entities/project.entity';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { User } from '../user/entities/user.entity';

@Injectable()
export class ProjectService {
  constructor(
    @InjectRepository(Project)
    private readonly projectRepo: Repository<Project>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  /**
   * Create a new project owned by the given userId.
   */
  async createProject(userId: number, dto: CreateProjectDto) {
    // Validate user existence if needed
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const project = this.projectRepo.create({
      name: dto.name,
      description: dto.description,
      projectData: dto.projectData,
      user,
    });
    return this.projectRepo.save(project);
  }

  /**
   * Get a single project by ID, ensuring it belongs to userId (if you want access control).
   */
  async getProjectById(userId: number, projectId: number) {
    const project = await this.projectRepo.findOne({
      where: { id: projectId, user: { id: userId } },
    });
    if (!project) {
      throw new NotFoundException('Project not found or not owned by user');
    }
    return project;
  }

  /**
   * Get all projects for a specific user.
   */
  async getProjectsForUser(userId: number) {
    return this.projectRepo.find({
      where: { user: { id: userId } },
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Update a project, ensuring it belongs to the user.
   */
  async updateProject(userId: number, projectId: number, dto: UpdateProjectDto) {
    // getProjectById also ensures user ownership
    const project = await this.getProjectById(userId, projectId);

    if (dto.name !== undefined) {
      project.name = dto.name;
    }
    if (dto.description !== undefined) {
      project.description = dto.description;
    }
    if (dto.projectData !== undefined) {
      project.projectData = dto.projectData;
    }
    // For example, you could also let them update isRendered or renderCount if needed

    return this.projectRepo.save(project);
  }

  /**
   * Soft-delete a project. The row stays in DB, but "deletedAt" is set.
   */
  async deleteProject(userId: number, projectId: number) {
    const project = await this.getProjectById(userId, projectId);
    await this.projectRepo.softRemove(project);
    return true; // or return the project object if needed
  }
}
