import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Project } from './entities/project.entity';
import { ProjectVersion } from './entities/project-version.entity';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { User } from '../user/entities/user.entity';
import { PaginationQueryDto } from 'src/common/dto/pagination.dto';
import { plainToClass } from 'class-transformer';
import { ProjectResponseDto } from './dto/project-response.dto';

@Injectable()
export class ProjectService {
  constructor(
    @InjectRepository(Project)
    private readonly projectRepo: Repository<Project>,
    @InjectRepository(ProjectVersion)
    private readonly versionRepo: Repository<ProjectVersion>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async createProject(userId: number, dto: CreateProjectDto) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const project = this.projectRepo.create({
      name: dto.name,
      description: dto.description,
      user
    });
    const savedProject = await this.projectRepo.save(project);

    const initialVersion = this.versionRepo.create({
      project: savedProject,
      versionNumber: 1,
      projectData: dto.projectData,
    });
    const savedVersion = await this.versionRepo.save(initialVersion);
    

    savedProject.currentVersion = savedVersion;
    await this.projectRepo.save(project);
    return plainToClass(ProjectResponseDto, savedProject, {
      excludeExtraneousValues: true,
    });
  }

  async getProjectById(userId: number, projectId: number) {
    const project = await this.projectRepo.findOne({
      where: { id: projectId, user: { id: userId } },
      relations: ['currentVersion', 'versions'],
    });
    if (!project) throw new NotFoundException('Project not found');
    // Transform the project entity to DTO
    return plainToClass(ProjectResponseDto, project, {
      excludeExtraneousValues: true,
    });
  }

  async getProjectsForUser(
    userId: number,
    pagination: PaginationQueryDto,
  ): Promise<{ projects: ProjectResponseDto[]; total: number; page: number; limit: number }> {
    const page = pagination.page || 1;
    const limit = pagination.limit || 10;
    const [projects, total] = await this.projectRepo.findAndCount({
      where: { user: { id: userId } },
      order: { createdAt: 'DESC' },
      skip: (page - 1) * limit,
      take: limit,
      relations: ['currentVersion'],
    });

    const data = projects.map(project =>
      plainToClass(ProjectResponseDto, project, { excludeExtraneousValues: true })
    );

    return { projects, total, page, limit };
  }

  async updateProject(userId: number, projectId: number, dto: UpdateProjectDto) {
    const project = await this.projectRepo.findOne({
      where: { id: projectId, user: { id: userId } },
      relations: ['versions'],
    });
    if (!project) throw new NotFoundException('Project not found');
  
    if (dto.name) project.name = dto.name;
    if (dto.description) project.description = dto.description;
  
    if (dto.projectData) {
      const latestVersion = await this.versionRepo.findOne({
        where: { project: { id: projectId } },
        order: { versionNumber: 'DESC' },
      });
      const newVersionNumber = latestVersion ? latestVersion.versionNumber + 1 : 1;
      const newVersion = this.versionRepo.create({
        project,
        versionNumber: newVersionNumber,
        projectData: dto.projectData,
      });
      const savedVersion = await this.versionRepo.save(newVersion);
      project.currentVersion = savedVersion;
    }
  
    return plainToClass(ProjectResponseDto, project, {
      excludeExtraneousValues: true,
    });
  }

  async getProjectVersions(userId: number, projectId: number) {
    await this.getProjectById(userId, projectId); // Verify ownership
    return this.versionRepo.find({
      where: { project: { id: projectId } },
      order: { versionNumber: 'ASC' },
    });
  }

  async deleteProject(userId: number, projectId: number) {
    const project = await this.getProjectById(userId, projectId);
    await this.projectRepo.softRemove(project);
    return true;
  }
}