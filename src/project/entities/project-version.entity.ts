import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn, DeleteDateColumn } from 'typeorm';
import { Project } from './project.entity';
import { Exclude } from 'class-transformer';

@Entity()
export class ProjectVersion {
    @PrimaryGeneratedColumn()
    id: number;

    @ManyToOne(() => Project, (project) => project.versions)
    project: Project;

    @Column()
    versionNumber: number;

    @Column('jsonb')
    projectData: any;

    @Exclude()
    @CreateDateColumn()
    createdAt: Date;

    @Exclude()
    @UpdateDateColumn()
    updatedAt: Date;

    @Exclude()
    @DeleteDateColumn()
    deletedAt?: Date;
}